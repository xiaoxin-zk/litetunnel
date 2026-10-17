package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestCreateTunnelUsesCurrentGroup 覆盖「创建隧道以**此刻**的套餐为准」。
//
// handler 传入的用户对象是请求开始时加载的快照；管理员改组后，快照里的
// 分组权限已经过时。按旧快照放行 UDP 的话，用户会建出一条新套餐不允许
// 的隧道，并一直带着越权参数跑下去。创建必须在事务内重读并锁定用户行
// 与分组行（用户行 → 分组行，与 AdminSetUserGroup 互斥）。
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

	// 快照：请求开始时用户还在 g1（允许 udp）。
	snapshot, err := svc.LoadUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}

	// 请求处理期间，管理员把用户改到了 g2（只允许 tcp）。
	if err := svc.AdminSetUserGroup(u.ID, g2.ID, GroupExpiry{}); err != nil {
		t.Fatalf("改组失败: %v", err)
	}

	// 按快照看 udp 是允许的，但按当前套餐必须被拒绝。
	_, err = svc.CreateTunnel(snapshot, TunnelInput{
		Name: "udptun", Type: model.ProxyTypeUDP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20061,
	})
	if !errors.Is(err, ErrProtocolDenied) {
		t.Fatalf("改组后在途请求不应再按旧套餐放行 udp，实际 %v", err)
	}

	// tcp 仍应成功，且限速快照来自新分组。
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

// TestEnsureTrafficPeriodCASOnConcurrentChange 覆盖周期重置的条件更新。
//
// 读到快照之后、重置执行之前，reset_at 被并发方改动（管理员清零）：
// 条件更新不命中，必须重读最终状态，而不是把内存里的零用量当事实。
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

	// 快照读完后，「并发方」把 reset_at 改到了未来（等价于管理员清零）。
	future := time.Now().AddDate(0, 1, 0)
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"traffic_used": 0, "traffic_reset_at": future}).Error; err != nil {
		t.Fatal(err)
	}

	svc.EnsureTrafficPeriod(u)

	// 内存对象必须与数据库最终状态一致，而不是快照里的旧值。
	if u.TrafficUsed != 0 {
		t.Fatalf("并发改动后应重读最终状态，内存用量 %d", u.TrafficUsed)
	}
	if !u.TrafficResetAt.Equal(future) {
		t.Fatalf("reset_at 应与数据库一致，实际 %v（期望 %v）", u.TrafficResetAt, future)
	}
}

// TestAdminResetUserTrafficSuppressesStaleDelta 覆盖「清零后旧增量不加回」。
//
// 清零后紧邻一轮的增量是清零前采样的旧流量；不协调的话，管理员清零完
// 最多一个采样周期后用量又冒出来。清零登记的待协调标记由 flushTraffic
// 消费：那一轮的增量被丢弃，之后恢复正常。
func TestAdminResetUserTrafficSuppressesStaleDelta(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	if err := svc.AdminResetUserTraffic(tun.UserID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}

	// 清零后的第一轮：带着清零前采样的旧增量 500——必须被丢弃。
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

	// 之后的轮次恢复正常：新增量 300 照常累加。
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

// 这个文件守的是「编辑隧道不能覆盖并发变更、更不能复活已删除的隧道」。
//
// UpdateTunnel 原先整行 Save：采集器并发写回的流量/在线时间会被编辑快照
// 覆盖掉；并发停用会被改回启用；删除先完成时，GORM 的 Save 在零行更新时
// 回退为插入——已删除的隧道被「编辑」复活。现在只更新可编辑字段并检查
// 影响行数，这些行为都能按顺序复现，不需要真正的并发。

func newEditTestTunnel(t *testing.T) (*Services, *model.User, *model.Tunnel) {
	t.Helper()
	svc := newTestServices(t, nil)
	// 用户与分组必须真实入库：隧道创建/编辑现在会在事务内按 GroupID
	// 重读并锁定分组行，内存态的 u.Group 不再参与判定。
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

// TestUpdateTunnelOnlyTouchesEditableFields 覆盖「只更新本次允许修改的字段」。
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
	// 状态、端口与流量不属于编辑范围：并发停用的状态、采集中的流量
	// 都不能被这次编辑改写。
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

// TestUpdateTunnelDoesNotReviveDeletedTunnel 覆盖「零行更新不得回退为插入」。
//
// 顺序复现删除竞态：删除先完成，随后的编辑必须返回 NotFound；
// 旧实现（整行 Save）在这里会把隧道重新插回去。
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

// TestSetTunnelStatusAfterDeleteIsNotFound 覆盖「状态接口在删除之后到达」。
//
// 调用方先读到隧道、再进入用户锁；若删除先拿到锁并完成，状态更新的
// 零行 UPDATE 原先会被当成成功——接口返回 200，状态根本没改。
// 现在锁内重读记录，记录已删就返回 NotFound。
func TestSetTunnelStatusAfterDeleteIsNotFound(t *testing.T) {
	svc, u, tun := newEditTestTunnel(t)

	// 先手工构造「调用方读到了记录」这一步，再删除。
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

// TestTruncateCutsAtRuneBoundary 覆盖「截断不得切断多字节字符」。
func TestTruncateCutsAtRuneBoundary(t *testing.T) {
	// 5 个汉字 = 15 字节，上限 7 字节会切在第 3 个字符中间。
	const s = "一二三四五"
	got := truncate(s, 7)
	if want := "一二"; got != want {
		t.Fatalf("应回退到字符边界，实际 %q（期望 %q）", got, want)
	}
	if !validUTF8(got) {
		t.Fatalf("截断结果必须是合法 UTF-8：%q", got)
	}
	// ASCII 与未超限的原样返回。
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
