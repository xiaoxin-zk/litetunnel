package router

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func newAdminTestPanel(t *testing.T, dbName string) (*config.Config, *service.Services, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), dbName),

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",
		AdminJWTExpire: time.Hour,

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
	t.Cleanup(func() { _ = sqlDB.Close() })

	if _, err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		t.Fatalf("播种初始数据失败: %v", err)
	}
	svc := service.New(db, cfg)

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)
	return cfg, svc, engine
}

func issueAdminToken(t *testing.T, cfg *config.Config, svc *service.Services, role string) string {
	t.Helper()
	a, err := svc.CreateAdmin(service.AdminCreateInput{
		Username: role + "_account",
		Password: "TestAdminPassw0rd!",
		Role:     role,
	})
	if err != nil {
		t.Fatalf("创建 %s 账号失败: %v", role, err)
	}
	token, _, err := auth.Issue(
		cfg.AdminJWTSecret, auth.DomainAdmin,
		a.ID, a.Username, a.Role, a.TokenVersion, cfg.AdminJWTExpire,
	)
	if err != nil {
		t.Fatalf("签发管理员令牌失败: %v", err)
	}
	return token
}

func callAdmin(t *testing.T, engine *gin.Engine, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// 审计只读角色必须能读、不能写。
// 读接口组曾经把它一并拒掉，导致该角色登录后连 /profile 都拿不到，
// 面板整个不可用——角色说明里写的却是「仅可查看数据」。
func TestAuditorCanReadButNotWrite(t *testing.T) {
	cfg, svc, engine := newAdminTestPanel(t, "rbac.db")
	token := issueAdminToken(t, cfg, svc, "auditor")

	for _, path := range []string{"/api/admin/profile", "/api/admin/alerts/events", "/api/admin/alerts/metrics"} {
		if rec := callAdmin(t, engine, token, http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Fatalf("审计只读访问 %s 返回 %d（期望 200）: %s", path, rec.Code, rec.Body.String())
		}
	}

	rec := callAdmin(t, engine, token, http.MethodPut, "/api/admin/alerts/settings", `{"enabled":false}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("审计只读修改告警设置返回 %d（期望 403）: %s", rec.Code, rec.Body.String())
	}
}

// 只提交部分字段时不能把没提交的项重置成零值：
// 只想调磁盘阈值，结果顺手把告警关掉，是很难在现场复现的事故。
func TestAlertSettingsPartialUpdateKeepsOtherFields(t *testing.T) {
	cfg, svc, engine := newAdminTestPanel(t, "alertpartial.db")
	token := issueAdminToken(t, cfg, svc, "super")

	rec := callAdmin(t, engine, token, http.MethodPut, "/api/admin/alerts/settings",
		`{"enabled":true,"webhook_url":"http://127.0.0.1:9/hook","error_rate_pct":7,"disk_pct":80,"backup_stale_hours":12}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存完整告警设置返回 %d: %s", rec.Code, rec.Body.String())
	}

	rec = callAdmin(t, engine, token, http.MethodPut, "/api/admin/alerts/settings", `{"disk_pct":95}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("部分更新返回 %d: %s", rec.Code, rec.Body.String())
	}

	got := svc.AlertConfig()
	if !got.Enabled {
		t.Error("只改磁盘阈值不该把告警关掉")
	}
	if got.DiskPct != 95 {
		t.Errorf("磁盘阈值 = %.0f，期望 95", got.DiskPct)
	}
	if got.ErrorRatePct != 7 || got.BackupStaleHr != 12 {
		t.Errorf("未提交的阈值被改动了: 错误率 %.0f，备份超时 %d", got.ErrorRatePct, got.BackupStaleHr)
	}
	if got.WebhookURL != "http://127.0.0.1:9/hook" {
		t.Errorf("未提交的 Webhook 被改动了: %q", got.WebhookURL)
	}
}
