// Package router 组装控制面的全部路由。
//
// 架构：用户控制台与管理后台**共用同一个公网端口**，通过路径区分：
//
//	/                用户控制台（SPA）
//	/api/user/*      用户侧接口
//	/admin           管理后台（SPA）
//	/api/admin/*     管理侧接口
//	/api/frps/plugin frps 服务端插件回调（仅受信网段）
//
// 安全依赖四层，缺一不可：
//  1. 令牌隔离：两套 JWT 使用不同密钥与不同 aud，令牌无法跨域使用；
//  2. 限流：按 IP 的令牌桶，管理侧策略更严；
//  3. 账号锁定：按账号的指数退避锁定，抵御代理池慢速爆破；
//  4. 双因素认证：管理员启用 TOTP 后，仅凭口令无法换取令牌。
//
// 可选地，可通过 LT_ADMIN_ALLOW_CIDR 把管理后台进一步限制到指定网段。
package router

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// New 构建唯一的公网入口。
func New(
	cfg *config.Config,
	svc *service.Services,
	authH *authapi.Handler,
	userH *userapi.Handler,
	adminH *adminapi.Handler,
	plugin *frpsplugin.Handler,
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.LimitBodySize(middleware.MaxRequestBodyBytes))
	r.Use(middleware.CORSDevOnly(cfg.IsProd()))

	// 只信任反代地址的转发头，防止客户端伪造来源 IP 绕过限流与白名单。
	//
	// 这里必须检查错误并 fail-fast，不能忽略：gin 在 New() 时默认把
	// trustedProxies 设为 ["0.0.0.0/0", "::/0"]（信任所有），而 SetTrustedProxies
	// 解析失败时会提前返回、**不更新内部的 trustedCIDRs**，于是保留「信任所有」。
	// 那样任何客户端都能伪造 X-Forwarded-For，限流与 LT_ADMIN_ALLOW_CIDR 全部失效。
	// 启动失败远好于静默地信任所有人。
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		panic(fmt.Sprintf("设置可信代理失败（会导致任意客户端伪造来源 IP）: %v", err))
	}

	// 健康检查。
	//
	// 生产环境刻意不返回版本号：那等于给攻击者一个现成的「按版本匹配已知漏洞」
	// 入口，而健康检查本身并不需要这个信息。非生产环境保留，
	// 便于本地与 CI 确认 ldflags 注入是否真的生效。
	r.GET("/healthz", func(c *gin.Context) {
		if cfg.IsProd() {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": config.Version})
	})

	// frps 服务端插件回调：仍严格限制为受信网段（默认仅回环），
	// 因为该接口的语义等同于「代 frps 做鉴权决策」，绝不可公网可达。
	r.POST("/api/frps/plugin", plugin.Guard(), plugin.Handle)

	adminAllow := middleware.NewCIDRSet(cfg.AdminAllowCIDRs)

	// 登录/注册类接口用更严格的限流，抵御撞库。
	userAuthLimiter := middleware.NewRateLimiter(0.5, 10)
	// 管理侧限流更严：它是公网可达的最高权限入口。
	adminAPILimiter := middleware.NewRateLimiter(20, 60)

	// 面板业务接口的限流阈值来自运行期配置，可在管理端「系统设置 → 接口限流」热调整。
	// 用动态限流器而不是固定值：不同规模的站点差异很大，写死会误伤或形同虚设。
	userAPILimiter := middleware.NewDynamicRateLimiter(func() (float64, float64) {
		perMinute := svc.Settings.Int(service.KeyAPIRatePerMinute)
		burst := svc.Settings.Int(service.KeyAPIRateBurst)
		return float64(perMinute) / 60.0, float64(burst)
	})

	// ================= 用户侧 =================

	// ================= 公共入口（无需认证）=================

	// 统一登录：用户控制台与管理后台共用一个入口，后端按账号自动分流。
	// 限流采用管理侧标准（更严），因为提交时无法预判账号属于哪一侧。
	pubAuthLimiter := middleware.NewRateLimiter(0.2, 5)
	pubAuth := r.Group("/api/auth")
	pubAuth.Use(middleware.Limit(pubAuthLimiter, "auth"))
	{
		pubAuth.POST("/login", authH.Login)
	}

	public := r.Group("/api/public")
	public.Use(middleware.Limit(userAPILimiter, "public"))
	{
		// 登录/注册之前就需要知道的站点信息与验证码。
		public.GET("/settings", authH.PublicSettings)
		public.GET("/captcha", authH.Captcha)
		public.POST("/captcha/verify", authH.VerifyCaptcha)
	}

	userAuth := r.Group("/api/user/auth")
	userAuth.Use(middleware.Limit(userAuthLimiter, "user-auth"))
	{
		userAuth.POST("/register", userH.Register)
		// 邮箱一次性验证码：注册验证与找回密码共用，scene 区分用途。
		userAuth.POST("/send-email-code", userH.SendEmailCode)
		// 找回密码：发信走异步队列，账号是否存在不会体现在响应上。
		userAuth.POST("/forgot-password", userH.ForgotPassword)
		userAuth.POST("/reset-password", userH.ResetPassword)
		userAuth.GET("/mail-status", userH.ResetMailStatus)
	}

	// 桌面客户端接入：同样是密码校验入口，必须同样限流 + 账号锁定。
	clientPub := r.Group("/api/user/client")
	clientPub.Use(middleware.Limit(userAuthLimiter, "user-client-auth"))
	{
		clientPub.POST("/auth", userH.ClientAuth)
	}

	// ================= 客户端接口组 =================
	//
	// 接受两种凭据：会话令牌（JWT）与长期凭据（API Key）。
	//
	// ## 权限边界：使用账号 vs 控制账号
	//
	// 这条线是整个设计里最需要想清楚的地方，因为它决定了一把可能泄露的
	// 钥匙能造成多大破坏。API Key 会以明文落在客户端本地配置文件里，
	// 因此不能让它等价于「账号被完全接管」。
	//
	//   允许（使用账号）：读信息、读写隧道、兑换码、看统计
	//     —— 这些就是客户端存在的意义。隧道是可删可重建的资源，
	//        兑换受分组限额约束，爆炸半径可控。
	//
	//   拒绝（控制账号）：改密码、改邮箱、重置 API Key、注销账号
	//     —— 这些是「账号接管」的关键步骤，一旦泄露即不可逆。
	//        它们保留在下面的 userAPI 组，只认会话令牌。
	//
	// 换句话说：一把可能泄露的钥匙，允许它开门，不允许它换锁。
	cli := r.Group("/api/user/client")
	cli.Use(middleware.Limit(userAPILimiter, "user-client"))
	cli.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{
		// 接入信息与配置
		cli.GET("/info", userH.ClientInfo)
		cli.GET("/config", userH.ClientConfig)

		// 隧道管理。远程端口留空时由服务端从端口池自动分配，
		// 并自动排除系统已占用与保留的端口——客户端不需要理解端口池。
		cli.GET("/tunnels", userH.ListTunnels)
		cli.POST("/tunnels", userH.CreateTunnel)
		cli.PUT("/tunnels/:id", userH.UpdateTunnel)
		cli.DELETE("/tunnels/:id", userH.DeleteTunnel)
		cli.POST("/tunnels/:id/status", userH.SetTunnelStatus)

		// 兑换码。同样受「不能是资产操作」的约束：
		// 兑换本身只是消费一个已发放的码，不会产生新的资产。
		cli.POST("/redeem", userH.Redeem)
		cli.GET("/redeem/records", userH.RedeemRecords)

		// 统计
		cli.GET("/stats/overview", userH.StatsOverview)
		cli.GET("/stats/traffic", userH.TrafficStats)

		// 客户端安装包。这一小组明确只读：即使以后有人加了写接口，
		// 也会被 ReadOnly 挡住（下载目录的内容是管理员放的）。
		dl := cli.Group("")
		dl.Use(middleware.ReadOnly())
		{
			dl.GET("/downloads", userH.ClientDownloads)
			dl.GET("/downloads/:name", userH.ClientDownloadFile)
		}
	}

	// ================= 账号接口组 =================
	//
	// 只接受会话令牌（JWT），API Key 一律拒绝。
	// 这里的每一个接口都能改变账号本身的安全状态，见上面的边界说明。
	userAPI := r.Group("/api/user")
	userAPI.Use(middleware.Limit(userAPILimiter, "user-api"))
	userAPI.Use(middleware.UserAuth(cfg.UserJWTSecret, svc.ResolveUserIdentity))
	userAPI.Use(middleware.RequireSession())
	{
		userAPI.GET("/profile", userH.Profile)
		userAPI.PUT("/profile", userH.UpdateProfile)
		// 注销账号：需要密码二次确认，且不可恢复。
		userAPI.DELETE("/profile", userH.DeleteAccount)
		userAPI.POST("/logout", userH.Logout)
		userAPI.PUT("/profile/password", userH.ChangePassword)

		// 凭据自身的管理：能重置 Key 就等于能复制身份，绝不能给 API Key。
		userAPI.GET("/apikey", userH.GetAPIKey)
		userAPI.POST("/apikey/reveal", userH.RevealAPIKey)
		userAPI.POST("/apikey/rotate", userH.RotateAPIKey)
	}

	// ================= 管理侧 =================

	adminRead := r.Group("/api/admin")
	adminRead.Use(middleware.Limit(adminAPILimiter, "admin-api"))
	adminRead.Use(adminAllow.Middleware())
	adminRead.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity))
	{
		adminRead.GET("/profile", adminH.Profile)
		// 改自己的资料 / 密码 / 双因素设置都不涉及他人，放在只读组，审计角色也能操作。
		adminRead.PUT("/profile", adminH.UpdateProfile)
		adminRead.PUT("/profile/password", adminH.ChangePassword)
		adminRead.POST("/profile/totp/setup", adminH.TOTPSetup)
		adminRead.POST("/profile/totp/enable", adminH.TOTPEnable)
		adminRead.POST("/profile/totp/disable", adminH.TOTPDisable)
		adminRead.GET("/stats/overview", adminH.StatsOverview)

		adminRead.GET("/users", adminH.ListUsers)
		adminRead.GET("/groups", adminH.ListGroups)
		adminRead.GET("/tunnels", adminH.ListTunnels)
		adminRead.GET("/redeem-codes", adminH.ListRedeemCodes)
		adminRead.GET("/redeem-records", adminH.ListRedeemRecords)
		adminRead.GET("/clients", adminH.ListClients)
		adminRead.GET("/audit-logs", adminH.ListAuditLogs)
		adminRead.GET("/login-logs", adminH.ListLoginLogs)
		adminRead.GET("/admins", adminH.ListAdmins)
		adminRead.GET("/settings", adminH.GetSettings)
	}

	// 写操作额外要求 super / operator 角色，auditor 只读。
	adminWrite := r.Group("/api/admin")
	adminWrite.Use(middleware.Limit(adminAPILimiter, "admin-write"))
	adminWrite.Use(adminAllow.Middleware())
	adminWrite.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity, "super", "operator"))
	{
		adminWrite.POST("/users", adminH.CreateUser)
		adminWrite.PUT("/users/:id", adminH.UpdateUser)
		adminWrite.DELETE("/users/:id", adminH.DeleteUser)
		adminWrite.POST("/users/:id/status", adminH.SetUserStatus)
		adminWrite.POST("/users/:id/quota", adminH.SetUserQuota)
		adminWrite.POST("/users/:id/traffic-reset", adminH.ResetUserTraffic)
		adminWrite.POST("/users/:id/group", adminH.SetUserGroup)
		adminWrite.POST("/users/:id/password", adminH.ResetUserPassword)
		adminWrite.POST("/users/:id/reset-secret", adminH.ResetUserSecret)

		adminWrite.POST("/groups", adminH.CreateGroup)
		adminWrite.PUT("/groups/:id", adminH.UpdateGroup)
		adminWrite.DELETE("/groups/:id", adminH.DeleteGroup)

		adminWrite.POST("/tunnels/:id/status", adminH.SetTunnelStatus)
		adminWrite.DELETE("/tunnels/:id", adminH.DeleteTunnel)

		adminWrite.POST("/redeem-codes/generate", adminH.GenerateRedeemCodes)
		adminWrite.POST("/redeem-codes/:id/status", adminH.SetRedeemCodeStatus)
		adminWrite.DELETE("/redeem-codes/:id", adminH.DeleteRedeemCode)
	}

	// 管理员账号管理仅限超级管理员：这是权限提升的关键路径，
	// 绝不能让 operator 通过创建管理员来给自己提权。
	adminSuper := r.Group("/api/admin")
	adminSuper.Use(middleware.Limit(adminAPILimiter, "admin-super"))
	adminSuper.Use(adminAllow.Middleware())
	adminSuper.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity, "super"))
	{
		adminSuper.POST("/admins", adminH.CreateAdmin)
		adminSuper.PUT("/admins/:id", adminH.UpdateAdmin)
		adminSuper.DELETE("/admins/:id", adminH.DeleteAdmin)
		adminSuper.POST("/admins/:id/password", adminH.SetAdminPassword)
		adminSuper.POST("/admins/:id/totp-reset", adminH.ClearAdminTOTP)

		// 系统设置含 SMTP 授权码与支付密钥，只有超级管理员可读写。
		adminSuper.PUT("/settings", adminH.UpdateSettings)
		adminSuper.POST("/settings/test-mail", adminH.TestMail)

		// 防火墙操作会改变主机网络可达性，属于高危操作，仅限超级管理员。
		adminSuper.GET("/firewall/status", adminH.FirewallStatus)
		adminSuper.POST("/firewall/rescan", adminH.FirewallRescan)
		adminSuper.POST("/firewall/ports", adminH.FirewallOpenPort)
		adminSuper.DELETE("/firewall/ports", adminH.FirewallClosePort)
	}

	serveSPA(r, cfg, adminAllow)
	return r
}

// serveSPA 托管两套单页应用。
//
// 目录不存在时静默跳过，服务以纯 API 模式运行（便于前后端分离开发）。
func serveSPA(r *gin.Engine, cfg *config.Config, adminAllow *middleware.CIDRSet) {
	userIndex, userOK := indexPath(cfg.UserWebDir)
	adminIndex, adminOK := indexPath(cfg.AdminWebDir)
	adminPath := cfg.AdminPath

	if adminOK {
		if assets := filepath.Join(cfg.AdminWebDir, "assets"); isDir(assets) {
			// 管理后台静态资源同样受白名单约束，避免受限 IP 看到半截页面。
			r.Group(adminPath, adminAllow.Middleware()).Static("/assets", assets)
		}
	}
	if userOK {
		if assets := filepath.Join(cfg.UserWebDir, "assets"); isDir(assets) {
			r.Static("/assets", assets)
		}
	}

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// 接口路径不做 SPA 回退，避免把 404 伪装成 200 页面。
		if strings.HasPrefix(path, "/api/") {
			httpx.NotFound(c, "接口不存在")
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			httpx.NotFound(c, "资源不存在")
			return
		}

		// 管理后台路径：先做白名单校验，未通过时按不存在处理。
		if isUnder(path, adminPath) {
			if !adminAllow.Contains(c.ClientIP()) || !adminOK {
				httpx.NotFound(c, "资源不存在")
				return
			}
			// 管理端前端使用相对资源路径，缺少结尾斜杠会让浏览器把
			// ./assets/... 解析到站点根目录。这里补一次跳转。
			if path == adminPath {
				c.Redirect(http.StatusFound, adminPath+"/")
				return
			}
			c.File(adminIndex)
			return
		}

		if !userOK {
			httpx.NotFound(c, "前端资源未构建")
			return
		}
		c.File(userIndex)
	})
}

func indexPath(dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	p := filepath.Join(dir, "index.html")
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// isUnder 判断 path 是否位于 prefix 之下（含 prefix 本身）。
func isUnder(path, prefix string) bool {
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
