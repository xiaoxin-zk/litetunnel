package router

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

const (
	policyAccount  = "policyuser"
	policyPassword = "PolicyPass123"
)

func newLoginPolicyStack(t *testing.T, captchaAfter string) (*gin.Engine, *service.Services) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "loginpolicy.db"),

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
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := service.New(db, cfg)
	t.Cleanup(svc.Close)

	ctx, cancel := context.WithCancel(context.Background())
	svc.StartLoginLogWriter(ctx)
	t.Cleanup(cancel)

	if err := svc.Settings.SetMany(map[service.SettingKey]string{
		service.KeyLoginCaptchaAfter: captchaAfter,
	}); err != nil {
		t.Fatalf("设置验证码阈值失败: %v", err)
	}

	hash, err := auth.HashPassword(policyPassword)
	if err != nil {
		t.Fatalf("生成口令哈希失败: %v", err)
	}
	if err := db.Create(&model.User{
		Username: policyAccount,
		Password: hash,
		Status:   model.UserStatusActive,
	}).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)
	return engine, svc
}

func postLogin(t *testing.T, engine *gin.Engine, path, account, password string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"username": account, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func captchaRequired(body map[string]any) bool {
	data, ok := body["data"].(map[string]any)
	if !ok {
		return false
	}
	v, _ := data["captcha_required"].(bool)
	return v
}

func waitFailedLoginLogged(t *testing.T, svc *service.Services, account string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if svc.CountRecentFailedLogins(model.LoginKindUser, account, 30*time.Minute) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("登录失败记录没有落库，账号级验证码要求不可能触发")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientAuthSharesLoginPolicy(t *testing.T) {
	engine, svc := newLoginPolicyStack(t, "1")

	if code, body := postLogin(t, engine, "/api/user/client/auth", policyAccount, policyPassword); code != http.StatusOK {
		t.Fatalf("干净账号用正确密码应当通过，实际 %d: %v", code, body)
	}

	if code, _ := postLogin(t, engine, "/api/user/client/auth", policyAccount, "definitely-wrong"); code == http.StatusOK {
		t.Fatal("错误密码不该通过")
	}
	waitFailedLoginLogged(t, svc, policyAccount)

	code, body := postLogin(t, engine, "/api/user/client/auth", policyAccount, policyPassword)
	if code != http.StatusUnauthorized || !captchaRequired(body) {
		t.Fatalf("账号累计失败后，桌面端接口必须要求人机验证，实际 code=%d body=%v", code, body)
	}

	code, body = postLogin(t, engine, "/api/auth/login", policyAccount, policyPassword)
	if code != http.StatusUnauthorized || !captchaRequired(body) {
		t.Fatalf("统一登录应当看到同一份计数并要求验证码，实际 code=%d body=%v", code, body)
	}
}

func TestClientAuthFailureCountsTowardUnifiedLock(t *testing.T) {
	engine, _ := newLoginPolicyStack(t, "10")

	for i := 0; i < 3; i++ {
		if code, _ := postLogin(t, engine, "/api/user/client/auth", policyAccount, "definitely-wrong"); code == http.StatusOK {
			t.Fatal("错误密码不该通过")
		}
	}

	code, body := postLogin(t, engine, "/api/auth/login", policyAccount, policyPassword)
	if code != http.StatusTooManyRequests {
		t.Fatalf("在客户端接口撞出的失败应当计入统一登录的锁定，实际 code=%d body=%v", code, body)
	}
}
