package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
)

// failingBackend 模拟「helper 在线、但底层防火墙状态查不到」。
type failingBackend struct{}

func (failingBackend) Name() string                        { return "iptables" }
func (failingBackend) Available() bool                     { return true }
func (failingBackend) Status() (bool, error)               { return false, errors.New("iptables 查询失败") }
func (failingBackend) ListRules() ([]firewall.Rule, error) { return nil, nil }
func (failingBackend) AddPort(int, string) error           { return nil }
func (failingBackend) RemovePort(int, string) error        { return nil }

// newTestHelper 起一个真实的 lt-fw /health 端点，返回面板侧的后端。
func newTestHelper(t *testing.T, be firewall.Backend) *firewall.HelperBackend {
	t.Helper()
	s := &server{token: "test-token", guard: firewall.NewGuard("", 1024, 65535), backend: be}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	srv := httptest.NewServer(s.auth(mux))
	t.Cleanup(srv.Close)
	return firewall.NewHelperBackend(srv.URL, "test-token")
}

// TestHealthReportsStatusError 覆盖「底层查询失败被报告成未启用」。
//
// helper 进程在线、但 iptables 查询失败时，/health 必须带上可区分的原因；
// 否则面板拿到的是 enabled=false、err=nil，新增的「未知」状态永远不生效，
// 界面会把一次查询失败显示成明确的「未生效」。
func TestHealthReportsStatusError(t *testing.T) {
	be := newTestHelper(t, failingBackend{})

	if !be.Available() {
		t.Fatal("helper 进程可达、后端自报可用：不该判成不可达")
	}
	if _, err := be.Status(); err == nil {
		t.Fatal("底层状态查询失败必须原样传到面板")
	}
}

// TestHealthReportsNoBackend 覆盖「没有可用后端时原因丢失」。
//
// None 是占位实现，它的 Available() 恒为 true；但对面板来说「没有可用的
// 防火墙后端」就是不可用，并且原因要能一路传到界面。
func TestHealthReportsNoBackend(t *testing.T) {
	be := newTestHelper(t, firewall.NewNone("宿主机没有可用的防火墙后端"))

	if be.Available() {
		t.Fatal("helper 自报没有可用后端时不该判成可用，否则写操作只会以 ErrNoBackend 失败")
	}
	if got := be.Reason(); got != "宿主机没有可用的防火墙后端" {
		t.Fatalf("原因应来自 helper，实际 %q", got)
	}
}
