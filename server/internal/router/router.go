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
	// 告警口径是「整个控制面的 5xx 比例」，因此在全局装统计中间件。
	r.Use(middleware.HTTPStatsMiddleware())
	r.Use(middleware.LimitBodySizeFor(middleware.MaxRequestBodyBytes, map[string]int64{
		"POST /api/admin/client-packages": service.MaxClientPackageSize + middleware.MultipartOverheadBytes,
	}))
	r.Use(middleware.CORSDevOnly(cfg.IsProd()))
	// 黑名单在鉴权之前生效：被封 IP 连登录接口都进不来。
	r.Use(middleware.BlockIPs(svc.BlockedPrefixes))

	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		panic(fmt.Sprintf("设置可信代理失败（会导致任意客户端伪造来源 IP）: %v", err))
	}

	r.GET("/healthz", func(c *gin.Context) {
		if cfg.IsProd() {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": config.DisplayVersion()})
	})

	r.POST("/api/frps/plugin", plugin.Guard(), plugin.Handle)

	adminAllow := middleware.NewCIDRSet(cfg.AdminAllowCIDRs)
	if bad := adminAllow.Invalid(); len(bad) > 0 {
		log.Printf("[router] LT_ADMIN_ALLOW_CIDR 有 %d 项无法解析，管理后台将拒绝所有来源: %v",
			len(bad), bad)
	}

	userAuthLimiter := middleware.NewRateLimiter(0.5, 10)
	adminAPILimiter := middleware.NewRateLimiter(20, 60)

	userAPILimiter := middleware.NewDynamicRateLimiter(func() (float64, float64) {
		perMinute := svc.Settings.Int(service.KeyAPIRatePerMinute)
		burst := svc.Settings.Int(service.KeyAPIRateBurst)
		return float64(perMinute) / 60.0, float64(burst)
	})

	pubAuthLimiter := middleware.NewRateLimiter(0.2, 5)
	pubAuth := r.Group("/api/auth")
	pubAuth.Use(middleware.Limit(pubAuthLimiter, "auth"))
	{
		pubAuth.POST("/login", authH.Login)
	}

	oauthPub := r.Group("/api/auth/oauth")
	oauthPub.Use(middleware.Limit(userAuthLimiter, "oauth"))
	{
		oauthPub.GET("/:provider/start", authH.OAuthStart)
		oauthPub.GET("/:provider/callback", authH.OAuthCallback)
	}

	public := r.Group("/api/public")
	public.Use(middleware.Limit(userAPILimiter, "public"))
	{
		public.GET("/settings", authH.PublicSettings)
		public.GET("/captcha", authH.Captcha)
		public.POST("/captcha/verify", authH.VerifyCaptcha)
	}

	userAuth := r.Group("/api/user/auth")
	userAuth.Use(middleware.Limit(userAuthLimiter, "user-auth"))
	{
		userAuth.POST("/register", userH.Register)
		userAuth.POST("/send-email-code", userH.SendEmailCode)
		userAuth.POST("/forgot-password", userH.ForgotPassword)
		userAuth.POST("/reset-password", userH.ResetPassword)
		userAuth.GET("/mail-status", userH.ResetMailStatus)
	}

	clientPub := r.Group("/api/user/client")
	clientPub.Use(middleware.Limit(userAuthLimiter, "user-client-auth"))
	{
		clientPub.POST("/auth", userH.ClientAuth)
	}

	cli := r.Group("/api/user/client")
	cli.Use(middleware.Limit(userAPILimiter, "user-client"))
	cli.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{
		cli.GET("/info", userH.ClientInfo)
		cli.GET("/version", userH.ClientVersion)
		cli.GET("/config", userH.ClientConfig)

		dl := cli.Group("")
		dl.Use(middleware.ReadOnly())
		{
			dl.GET("/downloads", userH.ClientDownloads)
			dl.GET("/downloads/:name", userH.ClientDownloadFile)
		}
	}

	userAPI := r.Group("/api/user")
	userAPI.Use(middleware.Limit(userAPILimiter, "user-api"))
	userAPI.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{

		userAPI.GET("/tunnels", userH.ListTunnels)
		userAPI.POST("/tunnels", userH.CreateTunnel)
		userAPI.POST("/tunnels/batch", userH.CreateTunnelsBatch)
		userAPI.PUT("/tunnels/:id", userH.UpdateTunnel)
		userAPI.DELETE("/tunnels/:id", userH.DeleteTunnel)
		userAPI.POST("/tunnels/:id/status", userH.SetTunnelStatus)

		userAPI.POST("/redeem", userH.Redeem)
		userAPI.GET("/redeem/records", userH.RedeemRecords)

		userAPI.GET("/stats/overview", userH.StatsOverview)
		userAPI.GET("/stats/traffic", userH.TrafficStats)

		account := userAPI.Group("")
		account.Use(middleware.RequireSession())
		{
			account.GET("/profile", userH.Profile)
			account.PUT("/profile", userH.UpdateProfile)
			account.DELETE("/profile", userH.DeleteAccount)
			account.POST("/logout", userH.Logout)
			account.PUT("/profile/password", userH.ChangePassword)
			account.POST("/profile/email-code", userH.RequestEmailChange)
			account.POST("/profile/email", userH.ConfirmEmailChange)

			account.GET("/apikey", userH.GetAPIKey)
			account.POST("/apikey/reveal", userH.RevealAPIKey)
			account.POST("/apikey/rotate", userH.RotateAPIKey)
		}
	}

	// 这一组是「只读 + 本人自助」：auditor 可以读所有列表，也可以改自己的资料/密码/双因素，
	// 这些操作只影响本人账号，不构成越权；所有影响他人或系统状态的写操作都在
	// 下面的 adminWrite / adminSuper 组，auditor 在那里会被拒。
	adminRead := r.Group("/api/admin")
	adminRead.Use(middleware.Limit(adminAPILimiter, "admin-api"))
	adminRead.Use(adminAllow.Middleware())
	adminRead.Use(middleware.AdminReadAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity, svc.ResolveAdminAPIKey))
	{
		adminRead.GET("/profile", adminH.Profile)
		adminRead.PUT("/profile", adminH.UpdateProfile)
		adminRead.PUT("/profile/password", adminH.ChangePassword)
		adminRead.POST("/profile/totp/setup", adminH.TOTPSetup)
		adminRead.POST("/profile/totp/enable", adminH.TOTPEnable)
		adminRead.POST("/profile/totp/disable", adminH.TOTPDisable)
		adminRead.GET("/stats/overview", adminH.StatsOverview)
		adminRead.GET("/system/metrics", adminH.SystemMetrics)
		adminRead.GET("/health", adminH.HealthReport)

		adminRead.GET("/users", adminH.ListUsers)
		adminRead.GET("/groups", adminH.ListGroups)
		adminRead.GET("/tunnels", adminH.ListTunnels)
		adminRead.GET("/redeem-codes", adminH.ListRedeemCodes)
		adminRead.GET("/redeem-records", adminH.ListRedeemRecords)
		adminRead.GET("/clients", adminH.ListClients)
		adminRead.GET("/client-packages", adminH.ListClientPackages)
		adminRead.GET("/audit-logs", adminH.ListAuditLogs)
		adminRead.GET("/login-logs", adminH.ListLoginLogs)
		adminRead.GET("/admins", adminH.ListAdmins)
		adminRead.GET("/settings", adminH.GetSettings)
		adminRead.GET("/mail-templates", adminH.ListMailTemplates)
		adminRead.GET("/domain/status", adminH.DomainStatus)
		adminRead.GET("/admin-api-keys", adminH.ListAdminAPIKeys)
		adminRead.GET("/backups", adminH.ListBackups)
		adminRead.GET("/alerts/settings", adminH.GetAlertSettings)
		adminRead.GET("/alerts/events", adminH.ListAlertEvents)
		adminRead.GET("/alerts/metrics", adminH.ListMetricSamples)
	}

	adminWrite := r.Group("/api/admin")
	adminWrite.Use(middleware.Limit(adminAPILimiter, "admin-write"))
	adminWrite.Use(adminAllow.Middleware())
	adminWrite.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity, "super", "operator"))
	{
		adminWrite.POST("/alerts/events/:id/resolve", adminH.ResolveAlertEvent)
		adminWrite.POST("/users", adminH.CreateUser)
		adminWrite.PUT("/users/:id", adminH.UpdateUser)
		adminWrite.DELETE("/users/:id", adminH.DeleteUser)
		adminWrite.POST("/users/:id/status", adminH.SetUserStatus)
		adminWrite.POST("/users/:id/quota", adminH.SetUserQuota)
		adminWrite.POST("/users/:id/traffic-reset", adminH.ResetUserTraffic)
		adminWrite.POST("/users/:id/group", adminH.SetUserGroup)
		adminWrite.POST("/users/:id/password", middleware.StepUp(svc), adminH.ResetUserPassword)
		adminWrite.POST("/users/:id/reset-secret", middleware.StepUp(svc), adminH.ResetUserSecret)
		adminWrite.POST("/step-up", adminH.StepUpVerify)
		adminWrite.GET("/system/update", adminH.CheckUpdate)

		adminWrite.POST("/groups", adminH.CreateGroup)
		adminWrite.PUT("/groups/:id", adminH.UpdateGroup)
		adminWrite.DELETE("/groups/:id", adminH.DeleteGroup)

		adminWrite.POST("/tunnels/:id/status", adminH.SetTunnelStatus)
		adminWrite.DELETE("/tunnels/:id", adminH.DeleteTunnel)

		adminWrite.POST("/redeem-codes/generate", adminH.GenerateRedeemCodes)
		adminWrite.POST("/redeem-codes/:id/status", adminH.SetRedeemCodeStatus)
		adminWrite.DELETE("/redeem-codes/:id", adminH.DeleteRedeemCode)
	}

	adminSuper := r.Group("/api/admin")
	adminSuper.Use(middleware.Limit(adminAPILimiter, "admin-super"))
	adminSuper.Use(adminAllow.Middleware())
	adminSuper.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity, "super"))
	adminSuper.Use(middleware.StepUp(svc))
	{
		adminSuper.POST("/admins", adminH.CreateAdmin)
		adminSuper.PUT("/admins/:id", adminH.UpdateAdmin)
		adminSuper.DELETE("/admins/:id", adminH.DeleteAdmin)
		adminSuper.POST("/admins/:id/password", adminH.SetAdminPassword)
		adminSuper.POST("/admins/:id/totp-reset", adminH.ClearAdminTOTP)

		adminSuper.POST("/backups", adminH.CreateBackup)
		adminSuper.GET("/backups/:name/download", adminH.DownloadBackup)
		adminSuper.DELETE("/backups/:name", adminH.DeleteBackup)
		adminSuper.POST("/backups/:name/restore", adminH.RestoreBackup)

		adminSuper.POST("/system/update/apply", adminH.ApplyUpdate)
		adminSuper.POST("/system/update/docker", adminH.ApplyDockerUpdate)
		adminSuper.POST("/system/update/restart", adminH.RestartPanel)

		adminSuper.PUT("/settings", adminH.UpdateSettings)
		adminSuper.POST("/settings/test-mail", adminH.TestMail)
		adminSuper.PUT("/alerts/settings", adminH.UpdateAlertSettings)
		adminSuper.POST("/alerts/settings/test", adminH.TestAlertWebhook)
		adminSuper.POST("/alerts/reports/test", adminH.SendTestReport)
		adminSuper.POST("/admin-api-keys", adminH.CreateAdminAPIKey)
		adminSuper.DELETE("/admin-api-keys/:id", adminH.RevokeAdminAPIKey)

		adminSuper.PUT("/mail-templates/:event", adminH.SaveMailTemplate)
		adminSuper.POST("/mail-templates/:event/preview", adminH.PreviewMailTemplate)
		adminSuper.DELETE("/mail-templates/:event", adminH.ResetMailTemplate)

		adminSuper.GET("/firewall/status", adminH.FirewallStatus)
		adminSuper.POST("/firewall/rescan", adminH.FirewallRescan)
		adminSuper.POST("/firewall/ports", adminH.FirewallOpenPort)
		adminSuper.DELETE("/firewall/ports", adminH.FirewallClosePort)
		adminSuper.POST("/firewall/failed/clear", adminH.FirewallClearFailed)

		adminSuper.POST("/domain/apply", adminH.DomainApply)
		adminSuper.POST("/domain/dns-check", adminH.DomainDNSCheck)

		adminSuper.POST("/client-packages", adminH.UploadClientPackage)
		adminSuper.DELETE("/client-packages/:name", adminH.DeleteClientPackage)
	}

	serveSPA(r, cfg, adminAllow)
	return r
}

func serveSPA(r *gin.Engine, cfg *config.Config, adminAllow *middleware.CIDRSet) {
	userIndex, userOK := indexPath(cfg.UserWebDir)
	adminIndex, adminOK := indexPath(cfg.AdminWebDir)
	adminPath := cfg.AdminPath

	if adminOK {
		if assets := filepath.Join(cfg.AdminWebDir, "assets"); isDir(assets) {
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

		if strings.HasPrefix(path, "/api/") {
			httpx.NotFound(c, "接口不存在")
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			httpx.NotFound(c, "资源不存在")
			return
		}

		if isUnder(path, adminPath) {
			if !adminAllow.Contains(c.ClientIP()) || !adminOK {
				httpx.NotFound(c, "资源不存在")
				return
			}
			if path == adminPath {
				c.Redirect(http.StatusFound, adminPath+"/")
				return
			}
			serveIndexHTML(c, adminIndex, config.DisplayVersion())
			return
		}

		if !userOK {
			httpx.NotFound(c, "前端资源未构建")
			return
		}
		serveIndexHTML(c, userIndex, config.DisplayVersion())
	})
}

// serveIndexHTML 把构建版本注入 index.html。
// 前端据此判断「加载的静态资源」与「后端版本」是否一致：容器升级后
// 仍停在旧页面的浏览器会提示刷新，避免新旧前端混用同一个后端。
func serveIndexHTML(c *gin.Context, file, version string) {
	data, err := os.ReadFile(file)
	if err != nil {
		c.File(file)
		return
	}
	html := strings.ReplaceAll(string(data), "__LT_VERSION__", version)
	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
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

func isUnder(path, prefix string) bool {
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
