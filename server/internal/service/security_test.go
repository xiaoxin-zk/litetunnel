package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func markTrafficBaselineReady(t *testing.T, svc *Services) {
	t.Helper()
	if err := svc.Settings.SetInternal(map[SettingKey]string{
		KeyTrafficBaselineReady:  "1",
		KeyTrafficResetMarkReady: "1",
	}); err != nil {
		t.Fatalf("写迁移标记失败: %v", err)
	}
}

func newTestServices(t *testing.T, cfg *config.Config) *Services {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Env = "test"
	cfg.LogLevel = "warn"
	cfg.DBDriver = "sqlite"
	if cfg.DBDSN == "" {
		cfg.DBDSN = filepath.Join(t.TempDir(), "test.db")
	}
	if cfg.APIKeyEncKey == "" {
		cfg.APIKeyEncKey = "test-api-key-enc"
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return New(db, cfg)
}

func mustAdmin(t *testing.T, svc *Services, username, role string) *model.Admin {
	t.Helper()
	a, err := svc.CreateAdmin(AdminCreateInput{
		Username: username,
		Password: "AdminPass12345",
		Role:     role,
	})
	if err != nil {
		t.Fatalf("建管理员 %s 失败: %v", username, err)
	}
	return a
}

func loadAdmin(t *testing.T, svc *Services, id uint) model.Admin {
	t.Helper()
	var a model.Admin
	if err := svc.DB.First(&a, id).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	return a
}

func newSuperAdmin(t *testing.T, svc *Services, name string) *model.Admin {
	t.Helper()
	a := &model.Admin{
		Username: name, Password: "not-used", Nickname: name,
		Role: "super", Status: "active", TokenVersion: 1,
	}
	if err := svc.DB.Create(a).Error; err != nil {
		t.Fatalf("建管理员 %s 失败: %v", name, err)
	}
	return a
}

func countActiveSupers(t *testing.T, svc *Services) int64 {
	t.Helper()
	var n int64
	if err := svc.DB.Model(&model.Admin{}).
		Where("role = ? AND status = ?", "super", "active").
		Count(&n).Error; err != nil {
		t.Fatalf("统计超级管理员失败: %v", err)
	}
	return n
}

func enableTestMail(t *testing.T, svc *Services) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeySMTPEnabled:  "true",
		KeySMTPHost:     "smtp.example.com",
		KeySMTPPort:     "587",
		KeySMTPUser:     "noreply@example.com",
		KeySMTPPassword: "secret",
		KeySMTPFrom:     "noreply@example.com",
		KeySMTPTLS:      "none",
	}); err != nil {
		t.Fatalf("设置邮件配置失败: %v", err)
	}
	if !svc.MailEnabled() {
		t.Fatal("前置条件：邮件应已启用")
	}
}

type fakeMailer struct {
	mu   sync.Mutex
	fail bool
	sent []string
}

func (f *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("smtp 不可用")
	}
	f.sent = append(f.sent, to)
	return nil
}

func (f *fakeMailer) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *fakeMailer) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func newMailTestServices(t *testing.T) (*Services, *fakeMailer) {
	t.Helper()
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	fm := &fakeMailer{}
	svc.mailerOverride = fm
	return svc, fm
}

func deliverAll(svc *Services) {
	svc.processMailOutbox(context.Background())
}

func enableTestFirewall(t *testing.T, svc *Services, helper *fakeFirewallHelper) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallAutoOpen:    "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}
}

type fakeFirewallHelper struct {
	*httptest.Server

	failCloses atomic.Bool
	failOpens  atomic.Bool

	closeEntered chan struct{}
	closeGate    chan struct{}

	mu     sync.Mutex
	opened []string
	closed []string
}

func newFakeFirewallHelper(t *testing.T) *fakeFirewallHelper {
	t.Helper()
	f := &fakeFirewallHelper{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"backend":"nft","available":true,"enabled":true}`))
		case "/ports/close":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.closeEntered != nil {
				select {
				case f.closeEntered <- struct{}{}:
				default:
				}
			}
			if f.closeGate != nil {
				<-f.closeGate
			}
			if f.failCloses.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.closed = append(f.closed, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/ports/open":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.failOpens.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.opened = append(f.opened, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeFirewallHelper) closedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.closed))
	copy(out, f.closed)
	return out
}

func (f *fakeFirewallHelper) openedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.opened))
	copy(out, f.opened)
	return out
}

func backdateSession(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[runID]
	if !ok {
		t.Fatalf("前置条件不成立：会话 %s 不存在", runID)
	}
	s.LastSeen = s.LastSeen.Add(-by)
	r.sessions[runID] = s
}

func backdateTouchAt(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.touchAt[runID]
	if !ok {
		t.Fatalf("前置条件不成立：节流记录 %s 不存在", runID)
	}
	r.touchAt[runID] = at.Add(-by)
}

type fakeFrpsTraffic struct {
	*httptest.Server
	total  atomic.Int64
	absent atomic.Bool
}

func newFakeFrpsTraffic(proxy string) *fakeFrpsTraffic {
	f := &fakeFrpsTraffic{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.absent.Load() {
			_, _ = w.Write([]byte(
				`{"code":200,"msg":"success","data":{"total":0,"page":1,"pageSize":200,"items":[]}}`))
			return
		}
		fmt.Fprintf(w,
			`{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":%q,"status":{"phase":"online","todayTrafficIn":%d,"todayTrafficOut":0,"curConns":0}}]}}`,
			proxy, f.total.Load())
	}))
	return f
}

func tunnelTrafficUsed(t *testing.T, svc *Services, id uint) int64 {
	t.Helper()
	var tun model.Tunnel
	if err := svc.DB.First(&tun, id).Error; err != nil {
		t.Fatalf("读隧道失败: %v", err)
	}
	return tun.TrafficUsed
}
