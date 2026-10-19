package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
)

type failingBackend struct{}

func (failingBackend) Name() string                        { return "iptables" }
func (failingBackend) Available() bool                     { return true }
func (failingBackend) Status() (bool, error)               { return false, errors.New("iptables 查询失败") }
func (failingBackend) ListRules() ([]firewall.Rule, error) { return nil, nil }
func (failingBackend) AddPort(int, string) error           { return nil }
func (failingBackend) RemovePort(int, string) error        { return nil }

func newTestHelper(t *testing.T, be firewall.Backend) *firewall.HelperBackend {
	t.Helper()
	s := &server{token: "test-token", guard: firewall.NewGuard("", 1024, 65535), backend: be}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	srv := httptest.NewServer(s.auth(mux))
	t.Cleanup(srv.Close)
	return firewall.NewHelperBackend(srv.URL, "test-token")
}

func TestHealthReportsStatusError(t *testing.T) {
	be := newTestHelper(t, failingBackend{})

	if !be.Available() {
		t.Fatal("helper 进程可达、后端自报可用：不该判成不可达")
	}
	if _, err := be.Status(); err == nil {
		t.Fatal("底层状态查询失败必须原样传到面板")
	}
}

func TestHealthReportsNoBackend(t *testing.T) {
	be := newTestHelper(t, firewall.NewNone("宿主机没有可用的防火墙后端"))

	if be.Available() {
		t.Fatal("helper 自报没有可用后端时不该判成可用，否则写操作只会以 ErrNoBackend 失败")
	}
	if got := be.Reason(); got != "宿主机没有可用的防火墙后端" {
		t.Fatalf("原因应来自 helper，实际 %q", got)
	}
}
