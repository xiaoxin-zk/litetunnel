package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func newForgotPasswordStack(t *testing.T, publicURL string) (*gin.Engine, *service.Services, *model.User) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "forgotpassword.db"),

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",

		UserPublicURL: publicURL,
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

	svc := service.New(db, cfg)

	if err := svc.Settings.SetMany(map[service.SettingKey]string{
		service.KeySMTPEnabled:  "true",
		service.KeySMTPHost:     "smtp.example.com",
		service.KeySMTPPort:     "587",
		service.KeySMTPUser:     "noreply@example.com",
		service.KeySMTPPassword: "secret",
		service.KeySMTPFrom:     "noreply@example.com",
	}); err != nil {
		t.Fatalf("设置邮件配置失败: %v", err)
	}
	if !svc.MailEnabled() {
		t.Fatal("前置条件：邮件应已启用")
	}

	u := &model.User{
		Username:      "forgotuser",
		Password:      "not-used-in-this-test",
		Email:         "forgot@example.com",
		EmailVerified: true,
		Status:        model.UserStatusActive,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)
	return engine, svc, u
}

func forgotPassword(t *testing.T, engine *gin.Engine, host, account string) *httptest.ResponseRecorder {
	t.Helper()

	body := fmt.Sprintf(`{"account":%q}`, account)
	req := httptest.NewRequest(http.MethodPost, "/api/user/auth/forgot-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func TestForgotPasswordDoesNotTrustRequestHost(t *testing.T) {
	engine, svc, u := newForgotPasswordStack(t, "")

	rec := forgotPassword(t, engine, "evil.example.com", u.Username)
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回统一提示，实际 %d: %s", rec.Code, rec.Body.String())
	}

	var n int64
	if err := svc.DB.Model(&model.MailOutbox{}).Count(&n).Error; err != nil {
		t.Fatalf("统计发件箱失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("未配置对外地址时不该发出任何邮件（链接只能由配置生成），实际 %d 封", n)
	}
}

func TestForgotPasswordLinkUsesConfiguredURL(t *testing.T) {
	const publicURL = "https://panel.example.com"
	engine, svc, u := newForgotPasswordStack(t, publicURL)

	rec := forgotPassword(t, engine, "evil.example.com", u.Username)
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回统一提示，实际 %d: %s", rec.Code, rec.Body.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartRecoveryWorker(ctx)
	var row model.MailOutbox
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := svc.DB.Where("to_addr = ?", u.Email).First(&row).Error; err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("后台应生成一封待发邮件")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(row.Body, publicURL+"/reset-password?token=") {
		t.Fatalf("链接必须用配置的对外地址生成，实际正文:\n%s", row.Body)
	}
	if strings.Contains(row.Body, "evil.example.com") {
		t.Fatal("正文里绝不能出现请求头里的 Host（Host 头投毒）")
	}
}
