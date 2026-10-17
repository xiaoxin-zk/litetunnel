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
	"log"
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
	// 全局 1 MiB，只给安装包上传开一个口子。
	//
	// 上传路由同样是普通 POST，会经过这条中间件：不开口子的话，一个 30 MB
	// 的客户端包在读取 FormFile 时就会失败，而错误信息只会说"请求体过大"，
	// 看起来像接口出了问题。上限按「文件上限 + multipart 余量」给，
	// 文件本身的约束仍由 service.SaveClientPackage 负责。
	r.Use(middleware.LimitBodySizeFor(middleware.MaxRequestBodyBytes, map[string]int64{
		"POST /api/admin/client-packages": service.MaxClientPackageSize + middleware.MultipartOverheadBytes,
	}))
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
	if bad := adminAllow.Invalid(); len(bad) > 0 {
		// 走到这里说明启动校验被绕过了（或有人直接构造了 CIDRSet）。
		// 这套集合此时会拒绝所有来源——记下来，否则表现只是「后台一律 404」。
		log.Printf("[router] LT_ADMIN_ALLOW_CIDR 有 %d 项无法解析，管理后台将拒绝所有来源: %v",
			len(bad), bad)
	}

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

	// ================= 客户端专属接口 =================
	//
	// 只放「桌面客户端才需要」的接入面：接入信息、frpc 配置、安装包。
	// 隧道管理与兑换等业务接口放在下面的 /api/user，两种入口共用同一批
	// handler——网页端用会话令牌，客户端用 API Key，不必注册两遍。
	cli := r.Group("/api/user/client")
	cli.Use(middleware.Limit(userAPILimiter, "user-client"))
	cli.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{
		cli.GET("/info", userH.ClientInfo)
		cli.GET("/config", userH.ClientConfig)

		// 客户端安装包。单独用 ReadOnly 包裹：目录内容由管理员放置，
		// 以后即使有人往这里加了写接口也写不进去。
		dl := cli.Group("")
		dl.Use(middleware.ReadOnly())
		{
			dl.GET("/downloads", userH.ClientDownloads)
			dl.GET("/downloads/:name", userH.ClientDownloadFile)
		}
	}

	// ================= 业务与账号接口 =================
	//
	// ## 权限边界：使用账号 vs 控制账号
	//
	// 这条线是整个设计里最需要想清楚的地方，因为它决定了一把可能泄露的
	// 钥匙能造成多大破坏。API Key 会以明文落在客户端本地配置文件里，
	// 因此不能让它等价于「账号被完全接管」。
	//
	//   允许（使用账号）：读写隧道、兑换码、看统计
	//     —— 这些就是客户端存在的意义。隧道是可删可重建的资源，
	//        兑换受分组限额约束，爆炸半径可控。
	//
	//   拒绝（控制账号）：改密码、改邮箱、重置 API Key、注销账号
	//     —— 这些是「账号接管」的关键步骤，一旦泄露即不可逆。
	//
	// 换句话说：一把可能泄露的钥匙，允许它开门，不允许它换锁。
	//
	// 实现上不再拆成两个组各注册一遍，而是同组内用 RequireSession
	// 划出内层——重复注册同一批 handler 是很容易漏掉一条的地方。
	userAPI := r.Group("/api/user")
	userAPI.Use(middleware.Limit(userAPILimiter, "user-api"))
	userAPI.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{
		// ---- 使用账号：两种凭据都放行 ----

		// 隧道管理。远程端口留空（0）时由服务端从端口池自动分配，
		// 并自动排除系统已占用与保留的端口——用户不需要理解端口池。
		userAPI.GET("/tunnels", userH.ListTunnels)
		userAPI.POST("/tunnels", userH.CreateTunnel)
		// 批量创建：一次映射一串连续端口（游戏服常见）。
		// 路径放在 /tunnels/batch，不会与 /tunnels/:id 冲突——
		// gin 对静态段优先于参数段。
		userAPI.POST("/tunnels/batch", userH.CreateTunnelsBatch)
		userAPI.PUT("/tunnels/:id", userH.UpdateTunnel)
		userAPI.DELETE("/tunnels/:id", userH.DeleteTunnel)
		userAPI.POST("/tunnels/:id/status", userH.SetTunnelStatus)

		// 兑换码：消费一个已发放的码，不产生新资产，故允许长期凭据。
		userAPI.POST("/redeem", userH.Redeem)
		userAPI.GET("/redeem/records", userH.RedeemRecords)

		userAPI.GET("/stats/overview", userH.StatsOverview)
		userAPI.GET("/stats/traffic", userH.TrafficStats)

		// ---- 控制账号：仅会话令牌 ----
		//
		// 这些接口能改变账号本身的安全状态，一旦被长期凭据调用，
		// 一份泄露的客户端配置就等于账号被接管。
		account := userAPI.Group("")
		account.Use(middleware.RequireSession())
		{
			account.GET("/profile", userH.Profile)
			account.PUT("/profile", userH.UpdateProfile)
			// 注销账号：需要密码二次确认，且不可恢复。
			account.DELETE("/profile", userH.DeleteAccount)
			account.POST("/logout", userH.Logout)
			account.PUT("/profile/password", userH.ChangePassword)
			// 更换邮箱：先给新地址发验证码、再带着验证码换绑。
			// 直接改 PUT /profile 里的 email 会被拒绝（见 UpdateProfile）。
			account.POST("/profile/email-code", userH.RequestEmailChange)
			account.POST("/profile/email", userH.ConfirmEmailChange)

			// 凭据自身的管理：能重置 Key 就等于能复制身份。
			account.GET("/apikey", userH.GetAPIKey)
			account.POST("/apikey/reveal", userH.RevealAPIKey)
			account.POST("/apikey/rotate", userH.RotateAPIKey)
		}
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
		// 服务器运行指标（CPU / 内存 / 网络 / 磁盘 / 负载 + 面板自身开销）。
		// 归在只读组：审计角色同样需要能看到机器状态。
		adminRead.GET("/system/metrics", adminH.SystemMetrics)

		adminRead.GET("/users", adminH.ListUsers)
		adminRead.GET("/groups", adminH.ListGroups)
		adminRead.GET("/tunnels", adminH.ListTunnels)
		adminRead.GET("/redeem-codes", adminH.ListRedeemCodes)
		adminRead.GET("/redeem-records", adminH.ListRedeemRecords)
		adminRead.GET("/clients", adminH.ListClients)
		// 客户端安装包分发。查看归只读组（审计角色也该能看），
		// 上传与删除仅超管——上传的文件会被分发给所有用户。
		adminRead.GET("/client-packages", adminH.ListClientPackages)
		adminRead.GET("/audit-logs", adminH.ListAuditLogs)
		adminRead.GET("/login-logs", adminH.ListLoginLogs)
		adminRead.GET("/admins", adminH.ListAdmins)
		adminRead.GET("/settings", adminH.GetSettings)
		// 「域名与证书」的状态：helper 健康度 + Caddy 证书 + 待检查域名。
		// 只读组：看证书什么时候到期，是审计角色也该能做的事。
		adminRead.GET("/domain/status", adminH.DomainStatus)
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
		adminSuper.POST("/firewall/failed/clear", adminH.FirewallClearFailed)

		// 域名与证书的下发会改宿主机上的 Caddyfile / frps.toml 并重建容器，
		// 配错直接等于「网站打不开、隧道全断」，因此仅超级管理员可操作。
		adminSuper.POST("/domain/apply", adminH.DomainApply)
		adminSuper.POST("/domain/dns-check", adminH.DomainDNSCheck)

		// 客户端安装包分发。上传的文件会被分发给所有用户下载，
		// 因此仅超级管理员可写（查看在只读组）。
		adminSuper.POST("/client-packages", adminH.UploadClientPackage)
		adminSuper.DELETE("/client-packages/:name", adminH.DeleteClientPackage)
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
