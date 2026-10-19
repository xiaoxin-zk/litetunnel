package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestCreateTunnelUsesCurrentGroup(t *testing.T) {
	cfg := &config.Config{PortRangeStart: 20000, PortRangeEnd: 21000}
	svc := newTestServices(t, cfg)

	g1 := &model.Group{Name: "full", AllowProtocols: "tcp,udp"}
	g2 := &model.Group{Name: "lite", AllowProtocols: "tcp"}
	for _, g := range []*model.Group{g1, g2} {
		if err := svc.DB.Create(g).Error; err != nil {
			t.Fatalf("建分组失败: %v", err)
		}
	}
	u := &model.User{Username: "groupswitch", Password: "not-used", Status: model.UserStatusActive, GroupID: g1.ID}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	snapshot, err := svc.LoadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.AdminSetUserGroup(u.ID, g2.ID, GroupExpiry{}); err != nil {
		t.Fatalf("改组失败: %v", err)
	}

	_, err = svc.CreateTunnel(snapshot, TunnelInput{
		Name: "udptun", Type: model.ProxyTypeUDP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20061,
	})
	if !errors.Is(err, ErrProtocolDenied) {
		t.Fatalf("改组后在途请求不应再按旧套餐放行 udp，实际 %v", err)
	}

	tun, err := svc.CreateTunnel(snapshot, TunnelInput{
		Name: "tcptun", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20062,
	})
	if err != nil {
		t.Fatalf("tcp 隧道应能创建: %v", err)
	}
	if tun.BandwidthLimit != g2.BandwidthLimit {
		t.Fatalf("限速快照应来自当前分组，实际 %d", tun.BandwidthLimit)
	}
}

func TestEnsureTrafficPeriodCASOnConcurrentChange(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "pgrp", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	u := &model.User{Username: "period", Password: "not-used", Status: model.UserStatusActive,
		GroupID: g.ID, TrafficUsed: 888,
		TrafficResetAt: time.Now().Add(-25 * time.Hour)}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}

	future := time.Now().AddDate(0, 1, 0)
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"traffic_used": 0, "traffic_reset_at": future}).Error; err != nil {
		t.Fatal(err)
	}

	svc.EnsureTrafficPeriod(u)

	if u.TrafficUsed != 0 {
		t.Fatalf("并发改动后应重读最终状态，内存用量 %d", u.TrafficUsed)
	}
	if !u.TrafficResetAt.Equal(future) {
		t.Fatalf("reset_at 应与数据库一致，实际 %v（期望 %v）", u.TrafficResetAt, future)
	}
}

func TestAdminResetUserTrafficSuppressesStaleDelta(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	if err := svc.AdminResetUserTraffic(tun.UserID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}

	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false, trafficFence{},
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 0 {
		t.Fatalf("清零后第一轮的旧增量不应加回，实际 %d", got)
	}

	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 300},
		nil, map[string]trafficPair{}, false, trafficFence{},
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 300 {
		t.Fatalf("后续增量应正常累加，实际 %d（期望 300）", got)
	}
}

func userTrafficUsed(t *testing.T, svc *Services, userID uint) int64 {
	t.Helper()
	var got int64
	if err := svc.DB.Model(&model.User{}).Where("id = ?", userID).
		Select("traffic_used").Row().Scan(&got); err != nil {
		t.Fatalf("读取用户用量失败: %v", err)
	}
	return got
}

func newEditTestTunnel(t *testing.T) (*Services, *model.User, *model.Tunnel) {
	t.Helper()
	svc := newTestServices(t, nil)
	g := &model.Group{Name: "editgrp", AllowProtocols: "tcp,udp,http,https", AllowCustomDomain: true}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u := &model.User{Username: "edituser", Password: "not-used", Status: model.UserStatusActive, GroupID: g.ID}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20051,
		Status: model.TunnelStatusDisabled, Remark: "old", TrafficUsed: 12345,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	return svc, u, tun
}

func TestUpdateTunnelOnlyTouchesEditableFields(t *testing.T) {
	svc, u, tun := newEditTestTunnel(t)

	updated, err := svc.UpdateTunnel(u, tun.ID, TunnelInput{
		Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "10.0.0.5", LocalPort: 3000,
		Remark: "new remark", UseEncryption: true,
	})
	if err != nil {
		t.Fatalf("编辑失败: %v", err)
	}
	if updated.LocalIP != "10.0.0.5" || updated.LocalPort != 3000 {
		t.Fatalf("可编辑字段应被更新: %+v", updated)
	}
	if updated.Remark != "new remark" || !updated.UseEncryption {
		t.Fatalf("备注与加密开关应被更新: %+v", updated)
	}
	if updated.Status != model.TunnelStatusDisabled {
		t.Fatalf("编辑不得改变启停状态，实际 %q", updated.Status)
	}
	if updated.RemotePort != 20051 {
		t.Fatalf("编辑不得改变远程端口，实际 %d", updated.RemotePort)
	}
	if updated.TrafficUsed != 12345 {
		t.Fatalf("编辑不得改写流量（采集器并发在写），实际 %d", updated.TrafficUsed)
	}
}

func TestUpdateTunnelDoesNotReviveDeletedTunnel(t *testing.T) {
	svc, u, tun := newEditTestTunnel(t)

	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}

	_, err := svc.UpdateTunnel(u, tun.ID, TunnelInput{
		Name: "mc", Type: model.ProxyTypeTCP, LocalIP: "127.0.0.1", LocalPort: 25565,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("编辑已删除的隧道应返回 NotFound，实际 %v", err)
	}

	var count int64
	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).Count(&count).Error; err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("已删除的隧道被编辑复活了：库里仍有 %d 条记录", count)
	}
}

func TestSetTunnelStatusAfterDeleteIsNotFound(t *testing.T) {
	svc, u, tun := newEditTestTunnel(t)

	var snapshot model.Tunnel
	if err := svc.DB.First(&snapshot, tun.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}

	err := svc.setTunnelStatus(&snapshot, model.TunnelStatusActive)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("对已删除隧道切换状态应返回 NotFound，实际 %v", err)
	}
}

func TestTruncateCutsAtRuneBoundary(t *testing.T) {
	const s = "一二三四五"
	got := truncate(s, 7)
	if want := "一二"; got != want {
		t.Fatalf("应回退到字符边界，实际 %q（期望 %q）", got, want)
	}
	if !validUTF8(got) {
		t.Fatalf("截断结果必须是合法 UTF-8：%q", got)
	}
	if got := truncate("hello", 3); got != "hel" {
		t.Fatalf("ASCII 截断应保持原行为，实际 %q", got)
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Fatalf("未超限不应改动，实际 %q", got)
	}
}

func validUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}
