package router

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

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

func TestClientConfigSingleTunnel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "clientconfig.db"),

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	if _, err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		t.Fatalf("播种初始数据失败: %v", err)
	}
	svc := service.New(db, cfg)

	owner := newTestUser(t, db, "cfgowner")
	other := newTestUser(t, db, "cfgother")

	mc1 := newTestTunnel(t, db, owner.ID, "mc1", 20011)
	mc2 := newTestTunnel(t, db, owner.ID, "mc2", 20012)
	otherTunnel := newTestTunnel(t, db, other.ID, "theirs", 20013)

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)

	apiKey, _, err := svc.RotateAPIKey(owner.ID)
	if err != nil {
		t.Fatalf("生成 API Key 失败: %v", err)
	}

	fetch := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/user/client/config"+query, nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}

	rec := fetch("")
	if rec.Code != http.StatusOK {
		t.Fatalf("整份配置返回 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	fullBody := body
	for _, name := range []string{mc1.Name, mc2.Name} {
		if !strings.Contains(body, `name = "`+name+`"`) {
			t.Fatalf("整份配置里缺少隧道 %q:\n%s", name, body)
		}
	}

	rec = fetch("?tunnel_id=" + uintStr(mc1.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("单条配置返回 %d: %s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, `name = "`+mc1.Name+`"`) {
		t.Fatalf("单条配置里没有请求的隧道 %q:\n%s", mc1.Name, body)
	}
	if strings.Contains(body, `name = "`+mc2.Name+`"`) {
		t.Fatalf("单条配置里混进了其他隧道 %q:\n%s", mc2.Name, body)
	}

	rev := rec.Header().Get("X-Config-Rev")
	if rev == "" {
		t.Fatal("配置响应必须带 X-Config-Rev（客户端据此跳过未变的拉取）")
	}
	if want := service.FrpcConfigRev(rec.Body.String()); rev != want {
		t.Fatalf("X-Config-Rev 与正文不一致: 头 %q, 正文哈希 %q", rev, want)
	}
	if rev == service.FrpcConfigRev(fullBody) {
		t.Fatal("单条配置与整份配置的正文不同，摘要不该相同")
	}

	rec = fetch("?tunnel_id=" + uintStr(otherTunnel.ID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("他人隧道 ID 返回 %d（期望 404）: %s", rec.Code, rec.Body.String())
	}

	for _, raw := range []string{"0", "abc", "-1", "99999999999999999999999"} {
		rec = fetch("?tunnel_id=" + raw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("tunnel_id=%q 返回 %d（期望 400）: %s", raw, rec.Code, rec.Body.String())
		}
	}
}

func newTestUser(t *testing.T, db *gorm.DB, name string) *model.User {
	t.Helper()
	u := &model.User{
		Username: name,
		Password: "not-used-in-this-test",
		Status:   model.UserStatusActive,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户 %s 失败: %v", name, err)
	}
	return u
}

func newTestTunnel(t *testing.T, db *gorm.DB, userID uint, name string, remotePort int) *model.Tunnel {
	t.Helper()
	tunnel := &model.Tunnel{
		UserID:     userID,
		Name:       name,
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: remotePort,
		Status:     model.TunnelStatusActive,
	}
	if err := db.Create(tunnel).Error; err != nil {
		t.Fatalf("建隧道 %s 失败: %v", name, err)
	}
	return tunnel
}

func uintStr(v uint) string {
	return strconv.FormatUint(uint64(v), 10)
}
