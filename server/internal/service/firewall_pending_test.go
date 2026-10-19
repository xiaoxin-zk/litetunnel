package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

func TestFirewallRetryExhaustionKeepsTerminalFailure(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, tun := exhaustClose(t, helper)

	if got := svc.PendingFirewallOps(); len(got) != 0 {
		t.Fatalf("耗尽后不应再出现在待重试列表，实际 %v", got)
	}

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

	if err := svc.ClearFirewallFailed(20031); err != nil {
		t.Fatalf("清除终态记录失败: %v", err)
	}
	if len(svc.FailedFirewallOps()) != 0 {
		t.Fatal("清除后终态列表应为空")
	}
	if err := svc.ClearFirewallFailed(20031); !errors.Is(err, ErrNotFound) {
		t.Fatalf("再次清除应报 NotFound，实际 %v", err)
	}

	_ = tun
}

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

func TestFirewallExhaustedRecordPrunedWhenStale(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, old := exhaustClose(t, helper)

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

	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的终态记录不应计入待处理，实际 %d", n)
	}
	if got := svc.FailedFirewallOps(); len(got) != 0 {
		t.Fatalf("已过时的终态记录应被作废，实际仍展示: %v", got)
	}
}

func TestFirewallNewIntentGetsFreshBudget(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc, tun := exhaustClose(t, helper)

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

	if n := svc.retryPendingFirewall(); n != 1 {
		t.Fatalf("新意图失败一次后应继续重试，实际剩余 %d", n)
	}
	if got := svc.PendingFirewallOps(); len(got) != 1 {
		t.Fatalf("新意图失败一次后不应被判为终态，实际 %v", got)
	}
}
