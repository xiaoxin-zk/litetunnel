package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「编辑隧道不能覆盖并发变更、更不能复活已删除的隧道」。
//
// UpdateTunnel 原先整行 Save：采集器并发写回的流量/在线时间会被编辑快照
// 覆盖掉；并发停用会被改回启用；删除先完成时，GORM 的 Save 在零行更新时
// 回退为插入——已删除的隧道被「编辑」复活。现在只更新可编辑字段并检查
// 影响行数，这些行为都能按顺序复现，不需要真正的并发。

func newEditTestTunnel(t *testing.T) (*Services, *model.User, *model.Tunnel) {
	t.Helper()
	svc := newTestServices(t, nil)
	u := &model.User{Username: "edituser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// EffectiveGroup 直接看 u.Group；测试环境没有默认分组，
	// 给个内存分组让协议校验通过即可。
	u.Group = &model.Group{AllowProtocols: "tcp,udp,http,https", AllowCustomDomain: true}
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
