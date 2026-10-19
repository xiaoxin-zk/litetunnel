package service

import (
	"fmt"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestActiveTunnelPortCount(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "fwport", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	mk := func(port int, proto, status string) {
		t.Helper()
		tun := &model.Tunnel{
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

	if n, err := svc.activeTunnelPortCount(20001, "tcp"); err != nil || n != 1 {
		t.Fatalf("20001/tcp 应有 1 条活跃隧道，实际 %d（err=%v）", n, err)
	}
	if n, err := svc.activeTunnelPortCount(20001, "udp"); err != nil || n != 1 {
		t.Fatalf("20001/udp 应有 1 条活跃隧道，实际 %d（err=%v）", n, err)
	}
	if n, err := svc.activeTunnelPortCount(20002, "tcp"); err != nil || n != 0 {
		t.Fatalf("已停用隧道不应占端口，实际 %d（err=%v）", n, err)
	}
	if n, err := svc.activeTunnelPortCount(20003, "tcp"); err != nil || n != 0 {
		t.Fatalf("空闲端口应计数为 0，实际 %d（err=%v）", n, err)
	}
}
