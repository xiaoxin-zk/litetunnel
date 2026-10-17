package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestFirewallCloseFailureIsRetried 覆盖「收回失败被吞掉」。
//
// 隧道停用/删除时数据库已经改了、接口也返回成功，而防火墙操作可能因为
// helper 暂时不可达而失败。以前只写一行日志：规则一直开着，而启动时的
// 规则对齐只补开、不收回，所以没有任何地方会再尝试。
func TestFirewallCloseFailureIsRetried(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "fwretry", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20007,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用：helper 此刻是坏的，操作仍然成功（数据库已改），但端口要进重试队列。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20007/tcp 待收回" {
		t.Fatalf("收回失败应进入待重试队列，实际 %v", pending)
	}

	// helper 恢复后重试应当成功，并且真的调到了 helper。
	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待收回端口，实际 %d 个", n)
	}
	closed := helper.closedPorts()
	if len(closed) != 1 || closed[0] != "20007/tcp" {
		t.Fatalf("重试应真的收回端口，实际 %v", closed)
	}
	if len(svc.PendingFirewallOps()) != 0 {
		t.Error("成功后应从待重试队列移除")
	}
}

// TestPendingCloseIsDroppedWhenPortIsReused 覆盖「旧任务关掉新隧道的端口」。
//
// 待办按端口保存，而端口会被复用：旧隧道删除后该端口分给了新隧道，
// 此时那条「收回 20001」的待办还在队列里——照着执行就会把新隧道的规则
// 一起关掉，用户看到的是「隧道莫名连不上」，而日志里只有一条「已补收回」。
func TestPendingCloseIsDroppedWhenPortIsReused(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "reuseuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 旧隧道：停用时收回失败，进入待办队列。
	old := &model.Tunnel{
		UserID: u.ID, Name: "old", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20011,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(old).Error; err != nil {
		t.Fatalf("建旧隧道失败: %v", err)
	}
	if err := svc.AdminSetTunnelStatus(old.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待收回记录，实际 %v", svc.PendingFirewallOps())
	}

	// 旧隧道被删除，端口 20011 分给了新隧道（且是启用状态）。
	if err := svc.AdminDeleteTunnel(old.ID); err != nil {
		t.Fatalf("删除旧隧道失败: %v", err)
	}
	fresh := &model.Tunnel{
		UserID: u.ID, Name: "new", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25566, RemotePort: 20011,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(fresh).Error; err != nil {
		t.Fatalf("建新隧道失败: %v", err)
	}

	// helper 恢复，重试——此时那条待办已经过时，必须作废而不是执行。
	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的待办应被作废，实际还剩 %d 条", n)
	}
	if got := helper.closedPorts(); len(got) != 0 {
		t.Fatalf("绝不能关掉已被新隧道复用的端口，实际关掉了 %v", got)
	}
}

// TestFirewallOpenFailureIsRetried 覆盖「放行失败没人重试」。
//
// 新建或启用隧道时会忽略 FirewallOpenPort 的错误，而防火墙协调器只在启动时
// 补开一次、之后只重试收回——helper 暂时不可用时，隧道一直处于启用状态但
// 端口没放行，只能靠人工重扫或重启服务。
func TestFirewallOpenFailureIsRetried(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failOpens.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "openretry", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20013,
		Status: model.TunnelStatusDisabled,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 启用：helper 坏的，数据库改了、放行失败，必须进入待办队列。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20013/tcp 待放行" {
		t.Fatalf("放行失败应进入待重试队列，实际 %v", pending)
	}

	// helper 恢复后重试应当真的放行。
	helper.failOpens.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	opened := helper.openedPorts()
	if len(opened) != 1 || opened[0] != "20013/tcp" {
		t.Fatalf("重试应真的放行端口，实际 %v", opened)
	}
}

// TestPendingOpenIsDroppedWhenTunnelDisabled 覆盖反面：
// 待放行的端口若隧道又被停用，重试不能把端口开回来。
func TestPendingOpenIsDroppedWhenTunnelDisabled(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failOpens.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "staleopen", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20015,
		Status: model.TunnelStatusDisabled,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待放行记录，实际 %v", svc.PendingFirewallOps())
	}

	// 用户又把它停用了（收回成功），此时那条待放行已经过时。
	helper.failOpens.Store(false)
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	helper.mu.Lock()
	helper.opened = nil
	helper.mu.Unlock()

	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的待放行应被作废，实际还剩 %d 条", n)
	}
	if got := helper.openedPorts(); len(got) != 0 {
		t.Fatalf("隧道已停用，绝不能把端口再开回来，实际 %v", got)
	}
}

// TestApplyPortIntentSkipsStaleClose 覆盖「立即路径不过时校验就动手」。
//
// 启停与删除都是「先改数据库、再动防火墙」，两步之间可能插进别的请求：
// 端口刚被新隧道占用，那条删除/停用的收回就会把新隧道的规则关掉。
// 动手前必须按当前状态确认意图仍然成立。
func TestApplyPortIntentSkipsStaleClose(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "staleclose", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20081,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 端口正被活跃隧道占用，此时「收回」的意图已经过时。
	acted, err := svc.applyPortIntent(20081, "tcp", false)
	if err != nil {
		t.Fatalf("不该有错误: %v", err)
	}
	if acted {
		t.Error("端口仍被活跃隧道占用，不该真的收回")
	}
	if got := helper.closedPorts(); len(got) != 0 {
		t.Fatalf("绝不能关掉活跃隧道的端口，实际关掉了 %v", got)
	}
	if got := svc.PendingFirewallOps(); len(got) != 0 {
		t.Errorf("过时的意图不该留下待办（否则会被反复重试），实际 %v", got)
	}
}

// TestApplyPortIntentSkipsStaleOpen 覆盖反面：没有隧道占用时不该放行。
//
// 对账拿的是某一刻的活跃隧道快照，逐条放行的过程中隧道可能已被停用或删除
// ——照着快照放行等于把一条已经不该开着的端口重新打开。
func TestApplyPortIntentSkipsStaleOpen(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	// 该端口没有任何隧道占用。
	acted, err := svc.applyPortIntent(20083, "tcp", true)
	if err != nil {
		t.Fatalf("不该有错误: %v", err)
	}
	if acted {
		t.Error("端口没有隧道占用，不该放行")
	}
	if got := helper.openedPorts(); len(got) != 0 {
		t.Fatalf("不该放行无归属的端口，实际 %v", got)
	}
}

// TestRetryKeepsNewIntentWrittenDuringOperation 覆盖「旧重试覆盖新意图」。
//
// 重试曾经在执行完 helper 操作后就释放端口锁，再回头更新/删除待办。这段间隙里
// 同一端口可能被写入**新意图**（刚停用的隧道又被启用），旧重试随后把新意图删掉
// ——那条真正需要的放行再也不会被重试，规则与数据库状态长期不一致。
//
// 现在「执行结果 + 待办状态提交」在同一段端口锁内，新意图只可能排在它之后写入。
func TestRetryKeepsNewIntentWrittenDuringOperation(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "intentrace", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20061,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用（helper 坏的）→ 产生「待收回」。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待收回，实际 %v", svc.PendingFirewallOps())
	}

	// 让重试的关端口卡在 helper 里，好在这期间插入新意图。
	helper.failCloses.Store(false)
	helper.failOpens.Store(true) // 新意图的放行会失败 → 必须留下待办
	helper.closeEntered = make(chan struct{}, 1)
	helper.closeGate = make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.retryPendingFirewall()
	}()

	select {
	case <-helper.closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("重试没有进入 helper 调用")
	}

	// 隧道被重新启用：产生新意图「待放行」。
	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("status", model.TunnelStatusActive).Error; err != nil {
		t.Fatalf("改状态失败: %v", err)
	}
	intentDone := make(chan struct{})
	go func() {
		defer close(intentDone)
		svc.applyPortIntent(20061, "tcp", true)
	}()

	close(helper.closeGate) // 放行重试继续
	<-done
	<-intentDone

	// 新意图必须还在：否则那条真正需要的放行不会再被重试。
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20061/tcp 待放行" {
		t.Fatalf("新意图被旧重试覆盖或删除，实际 %v", pending)
	}
}

// TestDeleteTunnelQueuesFirewallClose 覆盖「用户删除单条隧道时忽略收回失败」。
//
// 这条路径原先直接调 FirewallClosePort 并丢掉返回值：helper 恰好不可用时，
// 记录已经删了、端口号再也查不回来，规则就永久留在宿主机防火墙上，
// 而且没有任何地方会再尝试收回。
func TestDeleteTunnelQueuesFirewallClose(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "deltun", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20021,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除隧道失败: %v", err)
	}

	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20021/tcp 待收回" {
		t.Fatalf("收回失败应进入待重试队列，实际 %v", pending)
	}
}

// TestPendingFirewallSurvivesRestart 覆盖「待办只存在内存里」。
//
// 关闭失败后若服务重启，那条意图就没了；而启动时的规则对齐**只补放行、
// 不回收**，于是旧规则会长期残留——端口对外开着，面板上那条隧道却早已
// 停用或删除，看不出任何异常。所以待办必须落库并在启动时恢复。
func TestPendingFirewallSurvivesRestart(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "restart", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20023,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除隧道失败: %v", err)
	}

	var stored int64
	if err := svc.DB.Model(&model.FirewallPending{}).Where("port = ?", 20023).
		Count(&stored).Error; err != nil {
		t.Fatalf("统计待办失败: %v", err)
	}
	if stored != 1 {
		t.Fatalf("待办必须落库，实际库里 %d 条", stored)
	}

	// 模拟重启：同一个数据库上新建一套 Services（内存态是空的）。
	restarted := New(svc.DB, svc.Cfg)
	if len(restarted.PendingFirewallOps()) != 0 {
		t.Fatal("前置条件：新实例的内存队列应当是空的")
	}
	restarted.loadPendingFirewall()

	pending := restarted.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20023/tcp 待收回" {
		t.Fatalf("重启后应恢复待办，实际 %v", pending)
	}

	// helper 恢复后，重启后的实例应当能把它真正收回。
	helper.failCloses.Store(false)
	if n := restarted.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	closed := helper.closedPorts()
	if len(closed) != 1 || closed[0] != "20023/tcp" {
		t.Fatalf("重启恢复的待办应真的收回端口，实际 %v", closed)
	}
}

// TestEnablingFirewallAtRuntimeAlignsRules 覆盖「运行中开启防火墙不生效」。
//
// 协调器原先在启动时读一次设置，关着就整个协程都不启动——管理员中途在面板
// 上打开防火墙后，既没有规则对齐、也没有 worker 重试待办，已有的活跃隧道
// 不会被放行，要重启服务才生效，而界面完全不提示。
func TestEnablingFirewallAtRuntimeAlignsRules(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	// 注意：这里**不**打开防火墙，模拟「启动时是关着的」。
	u := &model.User{Username: "runtimeon", Password: "not-used", Status: model.UserStatusActive}
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

	svc.StartFirewallReconciler()
	// 协调器先睡 3 秒等 frps 与数据库就绪（见实现）。
	time.Sleep(3*time.Second + 300*time.Millisecond)

	// 运行中打开防火墙，并立刻唤醒协调器（设置页会这么做）。
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallAutoOpen:    "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("打开防火墙失败: %v", err)
	}
	svc.KickFirewall()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range helper.openedPorts() {
			if p == "20031/tcp" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("运行中打开防火墙后应对齐已有活跃隧道（放行 20031/tcp），实际已放行 %v",
		helper.openedPorts())
}

// TestRetryWaitsForPortLock 覆盖「校验意图与执行关闭之间的并发窗口」。
//
// 只校验不互斥的话仍有窗口：校验通过（此刻确实该关）→ 新隧道拿到这个端口
// 并放行 → 我们按旧意图把它关掉，新隧道刚建好就连不上。
// 竞态本身无法稳定复现，所以这里验证的是结构前提：重试会先取端口锁。
func TestRetryWaitsForPortLock(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "portlock", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20041,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	pl := svc.portLock(20041)
	pl.Lock() // 模拟「该端口的归属正在变化」

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.retryPendingFirewall()
	}()

	select {
	case <-done:
		t.Fatal("重试必须先取端口锁：否则校验与执行之间会插进新隧道的分配")
	case <-time.After(300 * time.Millisecond):
	}

	pl.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("释放端口锁后重试应立即继续")
	}
}

// TestCreateTunnelTakesPortLock 覆盖建隧道侧的结构前提。
//
// 取锁必须发生在**事务提交之前**：待办重试会先查数据库确认这个端口确实不该
// 开着，若此时创建事务尚未提交，它查不到这条新隧道就会认为可以关——随后
// 我们提交、放行，它紧接着把端口关掉。
//
// 并且必须在**事务开始之前**取：SQLite 只有一条连接，在事务里等端口锁会
// 把唯一连接一起占住，而「持有端口锁 → 查库」的那一侧（手工关闭端口、
// 待办重试）此时正等连接——两边都不超时，整个面板卡死。
func TestCreateTunnelTakesPortLock(t *testing.T) {
	// 指定端口必须落在配置的端口池范围内，所以这里给一个覆盖测试端口的区间。
	svc := newTestServices(t, &config.Config{PortRangeStart: 20000, PortRangeEnd: 20100})

	u := &model.User{Username: "createlock", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	g := &model.Group{
		Name: "锁测试组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20,
		AllowProtocols: "tcp", IsDefault: true,
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u.GroupID = g.ID

	pl := svc.portLock(20043)
	pl.Lock()

	done := make(chan error, 1)
	go func() {
		_, err := svc.CreateTunnel(u, TunnelInput{
			Name: "mc", Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20043,
		})
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("建隧道应等待该端口的锁（实际立即返回，err=%v）", err)
	case <-time.After(300 * time.Millisecond):
	}

	// 此刻建隧道正停在端口锁上。数据库必须仍然可用：它若在事务内等锁，
	// 就会占住 SQLite 那唯一一条连接，而手工关闭端口（端口锁内查库）
	// 与待办重试正需要这条连接——两边互相等，谁也不超时。
	dbDone := make(chan error, 1)
	go func() {
		var n int64
		dbDone <- svc.DB.Model(&model.Tunnel{}).Where("user_id = ?", u.ID).Count(&n).Error
	}()
	select {
	case err := <-dbDone:
		if err != nil {
			t.Fatalf("等待端口锁期间数据库查询失败: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待端口锁期间数据库被占住：建隧道不得在持有事务连接时等端口锁")
	}

	pl.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("释放端口锁后建隧道应成功，实际 %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("释放端口锁后建隧道应立即继续")
	}
}

// TestAdminTunnelOpsTouchFirewall 覆盖「管理员操作不联动防火墙」。
//
// 用户侧的启停与删除都会开关端口，管理员侧却只改数据库：后台显示「已停用」，
// 主机防火墙上的规则仍然放行；删除后规则更是永久残留。
// 而启动时的规则对齐只负责「补开活跃端口」，不会清理这种残留。
func TestAdminTunnelOpsTouchFirewall(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "admintun", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20005,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用 → 收回端口
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("管理员停用失败: %v", err)
	}
	if got := helper.closedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员停用后应收回 20005/tcp，实际 %v", got)
	}

	// 启用 → 重新放行
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("管理员启用失败: %v", err)
	}
	if got := helper.openedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员启用后应重新放行 20005/tcp，实际 %v", got)
	}

	// 删除 → 收回端口
	if err := svc.AdminDeleteTunnel(tun.ID); err != nil {
		t.Fatalf("管理员删除失败: %v", err)
	}
	closed := helper.closedPorts()
	if len(closed) != 2 || closed[1] != "20005/tcp" {
		t.Fatalf("管理员删除后应再次收回 20005/tcp，实际 %v", closed)
	}
}

// TestAdminDeleteUserClosesFirewallPorts 覆盖「删除用户后规则残留」。
//
// 单条隧道删除会收回端口，但批量删除用户时不会——隧道记录删掉后端口号
// 再也查不回来，规则就永久留在宿主机防火墙上。而启动时的规则对齐只负责
// 「放行已有的」，刻意不清理孤立规则（判断哪些是孤立的很容易误删）。
func TestAdminDeleteUserClosesFirewallPorts(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "fwuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	for i, port := range []int{20001, 20002} {
		tun := &model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("mc%d", i), Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: port,
			Status: model.TunnelStatusActive,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("删除用户失败: %v", err)
	}

	got := helper.closedPorts()
	if len(got) != 2 {
		t.Fatalf("应回收 2 个端口，实际 %v", got)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for _, want := range []string{"20001/tcp", "20002/tcp"} {
		if !seen[want] {
			t.Errorf("端口 %s 未被回收，实际 %v", want, got)
		}
	}
}

// TestPortAllocationSkipsReservedPorts 覆盖「自动/手动分配落到保留端口」。
func TestPortAllocationSkipsReservedPorts(t *testing.T) {
	svc := newTestServices(t, &config.Config{PortRangeStart: 30000, PortRangeEnd: 30005})
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyPortReserved: "30000-30003",
	}); err != nil {
		t.Fatalf("设置保留端口失败: %v", err)
	}

	// 手动指定保留端口必须被拒。
	//
	// 事务必须显式提交/回滚：SQLite 上只开一条连接（store.Open 里
	// SetMaxOpenConns(1)），留着不关会让后面每个 Begin 都永远等不到连接。
	tx := svc.DB.Begin()
	err := svc.assertPortFree(tx, 30000)
	tx.Rollback()
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("保留端口应被拒绝，实际 %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "保留") {
		t.Fatalf("错误信息应说明是保留/系统占用，实际 %v", err)
	}

	// 自动分配不能落到保留端口上。
	for i := 0; i < 50; i++ {
		tx := svc.DB.Begin()
		p, aerr := svc.allocatePort(tx, 1)
		tx.Rollback()
		if aerr != nil {
			break // 池子里的可用端口已试完（可能被系统监听占用）
		}
		if p >= 30000 && p <= 30003 {
			t.Fatalf("自动分配不应返回保留端口 %d", p)
		}
	}
}
