package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「重试耗尽 ≠ 线索消失」。
//
// 防火墙重试有上限（pendingFWMaxAttempts），耗尽后自动处理终止。以前的做法
// 是直接删掉记录、只留一行日志——日志一滚动，那条「本该收回却一直开着」
// 或「该放行却没放行」的端口就再也无处可查：界面上隧道早已停用或删除，
// 一切正常，规则却在宿主机上永远留着（或缺失）。
//
// 正确行为是三件事同时成立：
//  1. 终态记录保留（内存 + 落库），不再自动重试；
//  2. 管理页能看到它（FailedOps），并能人工补做或清除；
//  3. 记录描述的事若已不复存在（端口被新隧道复用、状态已反转），
//     重试循环会顺手作废它——错误信息也要跟着世界走，不能永远挂着。

// exhaustClose 把一个停用隧道的端口收回失败，走满整轮重试上限。
func exhaustClose(t *testing.T, helper *fakeFirewallHelper) (*Services, *model.Tunnel) {
	t.Helper()
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "fwexhaust", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20031,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	// 每轮重试恰好失败一次；最后一轮触达上限，本轮就转为终态。
	for i := 1; i <= pendingFWMaxAttempts; i++ {
		want := 1
		if i == pendingFWMaxAttempts {
			want = 0
		}
		if n := svc.retryPendingFirewall(); n != want {
			t.Fatalf("第 %d 轮重试后待处理应为 %d，实际 %d", i, want, n)
		}
	}
	return svc, tun
}

// TestFirewallRetryExhaustionKeepsTerminalFailure 覆盖终态保留、不再自动重试、
// 以及管理员清除。这是「日志被滚动掉就再也没有线索」这个缺陷的主回归。
func TestFirewallRetryExhaustionKeepsTerminalFailure(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, tun := exhaustClose(t, helper)

	// 终态不再计入「待处理」——否则每轮日志都会报
	// 「仍有 N 个待处理」，而其中那条永远不会成功。
	if got := svc.PendingFirewallOps(); len(got) != 0 {
		t.Fatalf("耗尽后不应再出现在待重试列表，实际 %v", got)
	}

	// 必须出现在终态列表里，且带上排查需要的全部要素。
	failed := svc.FailedFirewallOps()
	if len(failed) != 1 {
		t.Fatalf("耗尽后应保留 1 条终态失败记录，实际 %d 条", len(failed))
	}
	f := failed[0]
	if f.Port != 20031 || f.Proto != "tcp" || f.Open {
		t.Fatalf("终态记录字段不符: %+v", f)
	}
	if f.Attempts != pendingFWMaxAttempts {
		t.Fatalf("应保留累计重试次数 %d，实际 %d", pendingFWMaxAttempts, f.Attempts)
	}
	if f.LastErr == "" {
		t.Fatal("终态记录必须带上最后一次失败原因，否则管理员无从下手")
	}

	// helper 恢复也不该自动补做：终态的意思就是「不再自动动它」，
	// 否则管理员正在按记录手工处理时，后台又插一杠子。
	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("终态记录不应再被计入待处理，实际 %d", n)
	}
	if closed := helper.closedPorts(); len(closed) != 0 {
		t.Fatalf("终态记录不该被自动补做，实际补做了 %v", closed)
	}
	if len(svc.FailedFirewallOps()) != 1 {
		t.Fatal("自动重试轮不应动到终态记录")
	}

	// 清除：管理员处理完后把记录拿掉。
	if err := svc.ClearFirewallFailed(20031); err != nil {
		t.Fatalf("清除终态记录失败: %v", err)
	}
	if len(svc.FailedFirewallOps()) != 0 {
		t.Fatal("清除后终态列表应为空")
	}
	// 不存在或仍在重试队列里的记录不允许清除。
	if err := svc.ClearFirewallFailed(20031); !errors.Is(err, ErrNotFound) {
		t.Fatalf("再次清除应报 NotFound，实际 %v", err)
	}

	// 隧道还在（只是停用了）：清掉记录后没有别的线索了，这是管理员
	// 明确选择的结果，所以这里只验证记录确实被清掉。
	_ = tun
}

// TestFirewallExhaustionSurvivesRestart 覆盖「终态在重启后仍然保留」。
//
// 落库时若丢了 exhausted 标记，重启后这条记录会被当成普通待办
// 重新走满一轮上限——日志反复出现，终态展示时有时无。
func TestFirewallExhaustionSurvivesRestart(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, _ := exhaustClose(t, helper)

	restarted := New(svc.DB, svc.Cfg)
	restarted.loadPendingFirewall()

	if got := restarted.PendingFirewallOps(); len(got) != 0 {
		t.Fatalf("重启后终态记录不应进入重试队列，实际 %v", got)
	}
	failed := restarted.FailedFirewallOps()
	if len(failed) != 1 {
		t.Fatalf("重启后应仍有 1 条终态记录，实际 %d 条", len(failed))
	}
	if failed[0].Attempts != pendingFWMaxAttempts || failed[0].LastErr == "" {
		t.Fatalf("重启不应丢掉次数与最后错误: %+v", failed[0])
	}
}

// TestFirewallExhaustedRecordPrunedWhenStale 覆盖终态记录的过时清理。
//
// 端口被新隧道复用并启用后，「收回 20031」这件事已经不该发生了；
// 这时再展示那条失败记录就是在骗管理员。重试循环每轮会校验终态
// 记录的意图是否仍然成立，过时就作废。
func TestFirewallExhaustedRecordPrunedWhenStale(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, old := exhaustClose(t, helper)

	// 删掉旧隧道，把同一个端口分给新启用的隧道。
	if err := svc.AdminDeleteTunnel(old.ID); err != nil {
		t.Fatalf("删除旧隧道失败: %v", err)
	}
	u := &model.User{Username: "fwreuse", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	fresh := &model.Tunnel{
		UserID: u.ID, Name: "new", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20031,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(fresh).Error; err != nil {
		t.Fatalf("建新隧道失败: %v", err)
	}

	// 过时校验发生在重试循环里（它每轮都会跑）。
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的终态记录不应计入待处理，实际 %d", n)
	}
	if got := svc.FailedFirewallOps(); len(got) != 0 {
		t.Fatalf("已过时的终态记录应被作废，实际仍展示: %v", got)
	}
}

// TestFirewallNewIntentGetsFreshBudget 覆盖「耗尽后来了相反的意图」。
//
// 停用收回失败耗尽后，管理员又把隧道启用了：这是一次全新的意图，
// 应有自己完整的一轮重试预算；沿用旧计数会让它第一次失败就再次
// 被判为终态，等于永久拒绝这条隧道。
func TestFirewallNewIntentGetsFreshBudget(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, tun := exhaustClose(t, helper)

	// 重新启用：这次放行失败（换了个坏法），产生新意图。
	helper.failOpens.Store(true)
	helper.failCloses.Store(false)
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}

	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20031/tcp 待放行" {
		t.Fatalf("新意图应进入待重试队列，实际 %v", pending)
	}
	if got := svc.FailedFirewallOps(); len(got) != 0 {
		t.Fatalf("新意图不该被旧记录的耗尽状态连坐，实际 %v", got)
	}

	// 重试一次失败后仍应在重试队列（而不是立刻终态）：
	// 说明预算确实从零开始。
	if n := svc.retryPendingFirewall(); n != 1 {
		t.Fatalf("新意图失败一次后应继续重试，实际剩余 %d", n)
	}
	if got := svc.PendingFirewallOps(); len(got) != 1 {
		t.Fatalf("新意图失败一次后不应被判为终态，实际 %v", got)
	}
}
