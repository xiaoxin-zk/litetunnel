package service

import (
	"fmt"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这一组守的是「手工关闭端口与全量对齐的口径一致」：
// 对齐按「启用中的隧道」放行端口，所以只要还有活跃隧道占着端口，
// 手工关闭就该被拒绝——否则下一轮对齐会把它重新放行，管理员看到的
// 是「关掉了又自己开了」。

func TestActiveTunnelPortCount(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "fwport", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	mk := func(port int, proto, status string) {
		t.Helper()
		tun := &model.Tunnel{
			// 同一用户的隧道名唯一，名字带上端口与协议以免撞约束。
			UserID: u.ID, Name: fmt.Sprintf("%s-%d", proto, port), Type: proto,
			LocalIP:   "127.0.0.1",
			LocalPort: 25565, RemotePort: port, Status: status,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}
	mk(20001, model.ProxyTypeTCP, model.TunnelStatusActive)
	mk(20001, model.ProxyTypeUDP, model.TunnelStatusActive)
	mk(20002, model.ProxyTypeTCP, model.TunnelStatusDisabled)

	// tcp 端口：只有一条 tcp 活跃隧道占用。
	if n, err := svc.activeTunnelPortCount(20001, "tcp"); err != nil || n != 1 {
		t.Fatalf("20001/tcp 应有 1 条活跃隧道，实际 %d（err=%v）", n, err)
	}
	// udp 端口：udp 那条占用。
	if n, err := svc.activeTunnelPortCount(20001, "udp"); err != nil || n != 1 {
		t.Fatalf("20001/udp 应有 1 条活跃隧道，实际 %d（err=%v）", n, err)
	}
	// 已停用的隧道不占端口：对齐不会为它放行。
	if n, err := svc.activeTunnelPortCount(20002, "tcp"); err != nil || n != 0 {
		t.Fatalf("已停用隧道不应占端口，实际 %d（err=%v）", n, err)
	}
	// 端口无人使用：允许手工关闭。
	if n, err := svc.activeTunnelPortCount(20003, "tcp"); err != nil || n != 0 {
		t.Fatalf("空闲端口应计数为 0，实际 %d（err=%v）", n, err)
	}
}
