package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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

// 这一组守的是「重置链接的地址只能由服务端配置决定」。
//
// 找回密码的邮件里带着一个能改密码的令牌，而链接的域名以前是从请求的 Host
// 与 X-Forwarded-Proto 推断的——这两个头完全由请求方控制。攻击者往本接口
// 提交伪造的 Host，服务端就会把「指向攻击者域名」的链接发到用户邮箱里，
// 用户一点，令牌就交出去了（Host 头投毒）。
//
// 用例走的是真实路由 + 真实数据库，只把 SMTP 指向一个不会被真正使用的配置：
// 这里关心的是**链接怎么拼**，不是能不能发出去。

// newForgotPasswordStack 起一套真实栈，返回路由、服务集合与一个已绑定邮箱的用户。
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

		// 这正是被测的配置项。
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

	// 打开邮件开关：否则接口会因为「未配置邮件」提前返回，根本走不到拼接链接。
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
		Username: "forgotuser",
		Password: "not-used-in-this-test",
		Email:    "forgot@example.com",
		Status:   model.UserStatusActive,
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

// forgotPassword 带一个**伪造的 Host** 调用找回密码接口。
func forgotPassword(t *testing.T, engine *gin.Engine, host, account string) *httptest.ResponseRecorder {
	t.Helper()

	body := fmt.Sprintf(`{"account":%q}`, account)
	req := httptest.NewRequest(http.MethodPost, "/api/user/auth/forgot-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// 攻击者能完全控制这两个值，正是漏洞的入口。
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// TestForgotPasswordDoesNotTrustRequestHost 覆盖「未配置对外地址时退化为请求头」。
//
// 退化的结果是攻击者用伪造 Host 就能决定邮件里的链接指向哪里。正确行为是
// **不发这封信**：链接生成不出来就不发，而不是拿一个不可信的地址凑数。
// 对外仍返回统一提示——配置问题不该从响应里被看出来，更不能因此区分账号是否存在。
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

// TestForgotPasswordLinkUsesConfiguredURL 覆盖反面：配了对外地址时链接用配置值。
//
// 断言正文里出现配置的域名、且**不出现**请求头里的 Host——后者就是投毒的痕迹。
func TestForgotPasswordLinkUsesConfiguredURL(t *testing.T) {
	const publicURL = "https://panel.example.com"
	engine, svc, u := newForgotPasswordStack(t, publicURL)

	rec := forgotPassword(t, engine, "evil.example.com", u.Username)
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回统一提示，实际 %d: %s", rec.Code, rec.Body.String())
	}

	var row model.MailOutbox
	if err := svc.DB.Where("to_addr = ?", u.Email).First(&row).Error; err != nil {
		t.Fatalf("应有一封待发邮件: %v", err)
	}
	if !strings.Contains(row.Body, publicURL+"/reset-password?token=") {
		t.Fatalf("链接必须用配置的对外地址生成，实际正文:\n%s", row.Body)
	}
	if strings.Contains(row.Body, "evil.example.com") {
		t.Fatal("正文里绝不能出现请求头里的 Host（Host 头投毒）")
	}
}
