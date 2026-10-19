package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

type fakeFrps struct {
	*httptest.Server

	mu       sync.Mutex
	mode     string
	proxy    string
	requests int
}

func newFakeFrps() *fakeFrps {
	f := &fakeFrps{mode: "online"}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		mode, proxy := f.mode, f.proxy
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if mode == "garbage" {
			_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
			return
		}
		fmt.Fprintf(w,
			`{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":%q,"user":"lt_u1","clientID":"fake","status":{"phase":"online","todayTrafficIn":0,"todayTrafficOut":0,"curConns":0}}]}}`,
			proxy)
	}))
	return f
}

func (f *fakeFrps) setMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

func (f *fakeFrps) setProxy(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxy = name
}

func (f *fakeFrps) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestTunnelOnlineReachesClientAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var logs syncBuffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)

	frps := newFakeFrps()
	defer frps.Close()

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "tunnelonline.db"),

		FrpsAPIAddr:     frps.URL,
		FrpsAPIUser:     "admin",
		FrpsAPIPassword: "secret",

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",

		TrafficPollInterval: 5 * time.Second,
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if _, err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		t.Fatalf("播种初始数据失败: %v", err)
	}
	svc := service.New(db, cfg)

	u := &model.User{
		Username: "tunnelonline",
		Password: "not-used-in-this-test",
		Status:   model.UserStatusActive,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tunnel := &model.Tunnel{
		UserID:     u.ID,
		Name:       "mc",
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: 20001,
		Status:     model.TunnelStatusActive,
	}
	if err := db.Create(tunnel).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	frps.setProxy(service.FrpUserOf(u.ID) + "." + tunnel.Name)

	ctx, cancel := context.WithCancel(context.Background())
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	defer func() {
		cancel()
		_ = sqlDB.Close()
	}()

	svc.StartTrafficCollector(ctx)

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)

	apiKey, _, err := svc.RotateAPIKey(u.ID)
	if err != nil {
		t.Fatalf("生成 API Key 失败: %v", err)
	}

	waitOnline(t, engine, apiKey, tunnel.Name, true)

	before := frps.requestCount()
	frps.setMode("garbage")

	waitForLog(t, &logs, "保留上次在线状态", 10*time.Second)
	if got := frps.requestCount(); got <= before {
		t.Fatalf("假 frps 未收到新一轮请求（%d → %d）", before, got)
	}

	waitOnline(t, engine, apiKey, tunnel.Name, true)
}

func getTunnelOnline(t *testing.T, engine *gin.Engine, apiKey, name string) (bool, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/user/client/info", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("接入信息接口返回 %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		Data struct {
			Tunnels []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
				Online bool   `json:"online"`
			} `json:"tunnels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("接入信息响应不是合法 JSON: %v", err)
	}
	for _, tn := range out.Data.Tunnels {
		if tn.Name == name {
			if tn.Status != model.TunnelStatusActive {
				t.Fatalf("隧道 %s 的 status = %q，期望 %q", name, tn.Status, model.TunnelStatusActive)
			}
			return tn.Online, rec.Body.String()
		}
	}
	t.Fatalf("接入信息里没有隧道 %q: %s", name, rec.Body.String())
	return false, ""
}

func waitOnline(t *testing.T, engine *gin.Engine, apiKey, name string, want bool) {
	t.Helper()

	var last string
	for i := 0; i < 15; i++ {
		online, raw := getTunnelOnline(t, engine, apiKey, name)
		last = raw
		if online == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("等待隧道 %s 的 online=%v 超时，最后一次响应: %s", name, want, last)
}

func waitForLog(t *testing.T, logs *syncBuffer, want string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if contains(logs.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待日志 %q 超时，当前日志:\n%s", want, logs.String())
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
