package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20007/tcp 待收回" {
		t.Fatalf("收回失败应进入待重试队列，实际 %v", pending)
	}

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

	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的待办应被作废，实际还剩 %d 条", n)
	}
	if got := helper.closedPorts(); len(got) != 0 {
		t.Fatalf("绝不能关掉已被新隧道复用的端口，实际关掉了 %v", got)
	}
}

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

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20013/tcp 待放行" {
		t.Fatalf("放行失败应进入待重试队列，实际 %v", pending)
	}

	helper.failOpens.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	opened := helper.openedPorts()
	if len(opened) != 1 || opened[0] != "20013/tcp" {
		t.Fatalf("重试应真的放行端口，实际 %v", opened)
	}
}

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

func TestApplyPortIntentSkipsStaleOpen(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

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

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待收回，实际 %v", svc.PendingFirewallOps())
	}

	helper.failCloses.Store(false)
	helper.failOpens.Store(true)
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

	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("status", model.TunnelStatusActive).Error; err != nil {
		t.Fatalf("改状态失败: %v", err)
	}
	intentDone := make(chan struct{})
	go func() {
		defer close(intentDone)
		svc.applyPortIntent(20061, "tcp", true)
	}()

	close(helper.closeGate)
	<-done
	<-intentDone

	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20061/tcp 待放行" {
		t.Fatalf("新意图被旧重试覆盖或删除，实际 %v", pending)
	}
}

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

	restarted := New(svc.DB, svc.Cfg)
	if len(restarted.PendingFirewallOps()) != 0 {
		t.Fatal("前置条件：新实例的内存队列应当是空的")
	}
	restarted.loadPendingFirewall()

	pending := restarted.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20023/tcp 待收回" {
		t.Fatalf("重启后应恢复待办，实际 %v", pending)
	}

	helper.failCloses.Store(false)
	if n := restarted.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	closed := helper.closedPorts()
	if len(closed) != 1 || closed[0] != "20023/tcp" {
		t.Fatalf("重启恢复的待办应真的收回端口，实际 %v", closed)
	}
}

func TestEnablingFirewallAtRuntimeAlignsRules(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
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

	ctx, cancel := context.WithCancel(context.Background())
	done := svc.StartFirewallReconciler(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("协调器未在退出信号后停止")
		}
	})
	time.Sleep(3*time.Second + 300*time.Millisecond)

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
	pl.Lock()

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

func TestCreateTunnelTakesPortLock(t *testing.T) {
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

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("管理员停用失败: %v", err)
	}
	if got := helper.closedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员停用后应收回 20005/tcp，实际 %v", got)
	}

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("管理员启用失败: %v", err)
	}
	if got := helper.openedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员启用后应重新放行 20005/tcp，实际 %v", got)
	}

	if err := svc.AdminDeleteTunnel(tun.ID); err != nil {
		t.Fatalf("管理员删除失败: %v", err)
	}
	closed := helper.closedPorts()
	if len(closed) != 2 || closed[1] != "20005/tcp" {
		t.Fatalf("管理员删除后应再次收回 20005/tcp，实际 %v", closed)
	}
}

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

func TestPortAllocationSkipsReservedPorts(t *testing.T) {
	svc := newTestServices(t, &config.Config{PortRangeStart: 30000, PortRangeEnd: 30005})
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyPortReserved: "30000-30003",
	}); err != nil {
		t.Fatalf("设置保留端口失败: %v", err)
	}

	tx := svc.DB.Begin()
	err := svc.assertPortFree(tx, 30000)
	tx.Rollback()
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("保留端口应被拒绝，实际 %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "保留") {
		t.Fatalf("错误信息应说明是保留/系统占用，实际 %v", err)
	}

	for i := 0; i < 50; i++ {
		tx := svc.DB.Begin()
		p, aerr := svc.allocatePort(tx, 1)
		tx.Rollback()
		if aerr != nil {
			break
		}
		if p >= 30000 && p <= 30003 {
			t.Fatalf("自动分配不应返回保留端口 %d", p)
		}
	}
}

type failingBackend struct{}

func (failingBackend) Name() string                        { return "fake" }
func (failingBackend) Available() bool                     { return true }
func (failingBackend) Status() (bool, error)               { return false, errors.New("status boom") }
func (failingBackend) ListRules() ([]firewall.Rule, error) { return nil, errors.New("rules boom") }
func (failingBackend) AddPort(int, string) error           { return nil }
func (failingBackend) RemovePort(int, string) error        { return nil }

func TestFirewallStatusKeepsQueryErrors(t *testing.T) {
	st := &FirewallStatus{}
	fillBackendState(st, failingBackend{})

	if !st.ActiveUnknown {
		t.Fatal("状态查询失败时必须标为未知，不能默认 false（那会被显示成「未生效」）")
	}
	if st.Active {
		t.Fatal("未知时不应给出「生效中」的结论")
	}
	for _, want := range []string{"status boom", "rules boom"} {
		if !strings.Contains(st.Error, want) {
			t.Fatalf("错误原因应包含 %q，实际 %q", want, st.Error)
		}
	}
}

func TestFirewallStatusOfReportsRuleReadFailure(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	st := svc.FirewallStatusOf()
	if st.ActiveUnknown {
		t.Fatal("/health 可用，生效状态应能读到，不该标为未知")
	}
	if !st.Active {
		t.Fatal("假 helper 的 /health 报告 enabled=true，生效状态应为真")
	}
	if !strings.Contains(st.Error, "读取防火墙规则失败") {
		t.Fatalf("规则读取失败必须写进 fw.error，实际 %q", st.Error)
	}
}

func withScanFailure(t *testing.T) {
	t.Helper()
	orig := listeningPortSet
	listeningPortSet = func() (map[string]bool, error) { return nil, errors.New("scan boom") }
	t.Cleanup(func() { listeningPortSet = orig })
}

func TestPortPoolUsageMarksListeningUnknown(t *testing.T) {
	svc := newTestServices(t, &config.Config{PortRangeStart: 32100, PortRangeEnd: 32109})
	withScanFailure(t)

	u := svc.PortPoolUsageOf()
	if !u.ListeningUnknown {
		t.Fatal("扫描失败时必须标记系统占用未知")
	}
	if !u.FreeUnknown {
		t.Fatal("系统占用未知时空闲量也必须未知，否则会报出一个偏高的可用量")
	}
	if u.Free != 0 {
		t.Fatalf("未知时空闲量应为 0（由 FreeUnknown 表明不可信），实际 %d", u.Free)
	}
	if !strings.Contains(u.ListeningError, "scan boom") {
		t.Fatalf("应带上扫描失败原因，实际 %q", u.ListeningError)
	}
	if !strings.Contains(strings.Join(u.Advice, " "), "系统监听") {
		t.Fatalf("提示里应说明是系统监听端口读取失败，实际 %v", u.Advice)
	}
}

func TestAllocatePortRejectsWhenScanFails(t *testing.T) {
	svc := newTestServices(t, &config.Config{PortRangeStart: 32200, PortRangeEnd: 32209})
	withScanFailure(t)

	if _, err := svc.allocatePort(svc.DB, 1); !errors.Is(err, ErrPortScanUnavailable) {
		t.Fatalf("扫描失败时必须拒绝分配并说明原因，实际 %v", err)
	}

	if err := svc.Settings.SetMany(map[SettingKey]string{KeyPortReserved: "32205"}); err != nil {
		t.Fatalf("设置保留端口失败: %v", err)
	}
	tx := svc.DB.Begin()
	err := svc.assertPortFree(tx, 32205)
	tx.Rollback()
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("保留端口不依赖扫描，命中时仍应报「已被占用」，实际 %v", err)
	}
}
