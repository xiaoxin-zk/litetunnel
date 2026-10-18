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

// 这一组守的是「校验密码的入口只有一套策略」。
//
// 背景：桌面端 /api/user/client/auth 与统一登录同样校验账号密码，但它曾经
// 只有一份独立的 IP 限流与锁定 scope，没有账号级验证码要求。而硬锁是按
// 「账号 + 来源 IP」计数的，分布式来源每个 IP 各拿一份额度——账号级验证码
// 要求才是分布式爆破的唯一克星。因此漏掉它的那个入口，就是一条完整的
// 爆破通道：攻击者在网页端撞几次、再改打客户端接口继续撞。
//
// 用例断言的是策略本身，而不是某个函数的实现：同一次失败之后，**两个入口
// 都必须要求验证码**，且拿正确密码也一样。

const (
	policyAccount  = "policyuser"
	policyPassword = "PolicyPass123"
)

// newLoginPolicyStack 起一套真实路由 + 真实数据库。
//
// captchaAfter 是「账号累计失败多少次后要求验证码」。它决定用例考察哪一层：
//
//	低值（如 "1"）：一次失败之后就进入验证码要求，用来考察账号级防线；
//	高值：阈值高于硬锁的 3 次，用来考察两个入口是否共用同一份硬锁计数。
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
	// Services 自带两个 gc 协程（验证码存储、登录锁定器），它们不监听 ctx，
	// 只能显式关闭；不关的话每个用例都会留下一个 ticker 协程。
	t.Cleanup(svc.Close)

	// 登录日志是异步落库的（内存队列 → 协程写库），而验证码要求是**查库**
	// 统计的。不把写库协程跑起来，计数永远是 0，用例会假通过。
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

// captchaRequired 读响应里机器可读的「需要验证码」标记。
func captchaRequired(body map[string]any) bool {
	data, ok := body["data"].(map[string]any)
	if !ok {
		return false
	}
	v, _ := data["captcha_required"].(bool)
	return v
}

// waitFailedLoginLogged 等这次的失败记录落库。登录日志走内存队列异步写库，
// 直接断言会有竞态。
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
	// 阈值 1：一次失败之后就应当要求验证码，而此时还没到硬锁的门槛，
	// 因此观察到的一定是账号级防线，而不是 429。
	engine, svc := newLoginPolicyStack(t, "1")

	// 对照组：还没有任何失败记录时，正确密码应当正常通过。少了它，下面的
	// 断言只能证明「接口坏了」，证明不了是验证码在起作用。
	if code, body := postLogin(t, engine, "/api/user/client/auth", policyAccount, policyPassword); code != http.StatusOK {
		t.Fatalf("干净账号用正确密码应当通过，实际 %d: %v", code, body)
	}

	// 制造一次真实的凭据失败。
	if code, _ := postLogin(t, engine, "/api/user/client/auth", policyAccount, "definitely-wrong"); code == http.StatusOK {
		t.Fatal("错误密码不该通过")
	}
	waitFailedLoginLogged(t, svc, policyAccount)

	// 断言 1：桌面端接口同样必须要求验证码——给对密码也不行。
	code, body := postLogin(t, engine, "/api/user/client/auth", policyAccount, policyPassword)
	if code != http.StatusUnauthorized || !captchaRequired(body) {
		t.Fatalf("账号累计失败后，桌面端接口必须要求人机验证，实际 code=%d body=%v", code, body)
	}

	// 断言 2：这份计数与统一登录是同一份。两个入口各自计数的话，攻击者只要
	// 在两者之间轮换，谁都到不了阈值。
	code, body = postLogin(t, engine, "/api/auth/login", policyAccount, policyPassword)
	if code != http.StatusUnauthorized || !captchaRequired(body) {
		t.Fatalf("统一登录应当看到同一份计数并要求验证码，实际 code=%d body=%v", code, body)
	}
}

// TestClientAuthFailureCountsTowardUnifiedLock 覆盖另一半：在桌面端接口上
// 撞出来的失败，也要算进统一登录的硬锁里（同一份 Guard 实例）。
func TestClientAuthFailureCountsTowardUnifiedLock(t *testing.T) {
	// 验证码阈值放到硬锁（3 次）之上，这样先触发的是锁，观察得到 429。
	engine, _ := newLoginPolicyStack(t, "10")

	// 在客户端接口上打满 3 次错误密码。
	for i := 0; i < 3; i++ {
		if code, _ := postLogin(t, engine, "/api/user/client/auth", policyAccount, "definitely-wrong"); code == http.StatusOK {
			t.Fatal("错误密码不该通过")
		}
	}

	// 第 4 次直接换统一登录入口：应当已经被锁定（429），而不是还能继续猜。
	code, body := postLogin(t, engine, "/api/auth/login", policyAccount, policyPassword)
	if code != http.StatusTooManyRequests {
		t.Fatalf("在客户端接口撞出的失败应当计入统一登录的锁定，实际 code=%d body=%v", code, body)
	}
}
