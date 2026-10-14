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
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
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
	_ = r.SetTrustedProxies(cfg.TrustedProxies)

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// frps 服务端插件回调：仍严格限制为受信网段（默认仅回环），
	// 因为该接口的语义等同于「代 frps 做鉴权决策」，绝不可公网可达。
	r.POST("/api/frps/plugin", plugin.Guard(), plugin.Handle)

	adminAllow := middleware.NewCIDRSet(cfg.AdminAllowCIDRs)

	// 登录/注册类接口用更严格的限流，抵御撞库。
	userAuthLimiter := middleware.NewRateLimiter(0.5, 10)
	userAPILimiter := middleware.NewRateLimiter(30, 90)
	// 管理侧限流更严：它是公网可达的最高权限入口。
	adminAuthLimiter := middleware.NewRateLimiter(0.1, 3)
	adminAPILimiter := middleware.NewRateLimiter(20, 60)

	// ================= 用户侧 =================

	userAuth := r.Group("/api/user/auth")
	userAuth.Use(middleware.Limit(userAuthLimiter, "user-auth"))
	{
		userAuth.POST("/register", userH.Register)
		userAuth.POST("/login", userH.Login)
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

	// 桌面客户端接口：支持 JWT 或长期凭据（API Key / 客户端接入凭据）。
	cli := r.Group("/api/user/client")
	cli.Use(middleware.Limit(userAPILimiter, "user-client"))
	cli.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.ResolveUserIdentity))
	{
		cli.GET("/info", userH.ClientInfo)
		cli.GET("/config", userH.ClientConfig)
		cli.GET("/downloads", userH.ClientDownloads)
		cli.GET("/downloads/:name", userH.ClientDownloadFile)
	}

	userAPI := r.Group("/api/user")
	userAPI.Use(middleware.Limit(userAPILimiter, "user-api"))
	userAPI.Use(middleware.UserAuth(cfg.UserJWTSecret, svc.ResolveUserIdentity))
	{
		userAPI.GET("/profile", userH.Profile)
		userAPI.PUT("/profile", userH.UpdateProfile)
		// 注销账号：需要密码二次确认，且不可恢复。
		userAPI.DELETE("/profile", userH.DeleteAccount)
		userAPI.POST("/logout", userH.Logout)
		userAPI.PUT("/profile/password", userH.ChangePassword)

		userAPI.GET("/tunnels", userH.ListTunnels)
		userAPI.POST("/tunnels", userH.CreateTunnel)
		userAPI.PUT("/tunnels/:id", userH.UpdateTunnel)
		userAPI.DELETE("/tunnels/:id", userH.DeleteTunnel)
		userAPI.POST("/tunnels/:id/status", userH.SetTunnelStatus)

		userAPI.GET("/apikey", userH.GetAPIKey)
		userAPI.POST("/apikey/reveal", userH.RevealAPIKey)
		userAPI.POST("/apikey/rotate", userH.RotateAPIKey)

		userAPI.POST("/redeem", userH.Redeem)
		userAPI.GET("/redeem/records", userH.RedeemRecords)

		userAPI.GET("/stats/overview", userH.StatsOverview)
		userAPI.GET("/stats/traffic", userH.TrafficStats)
	}

	// ================= 管理侧 =================

	adminAuth := r.Group("/api/admin/auth")
	adminAuth.Use(middleware.Limit(adminAuthLimiter, "admin-auth"))
	adminAuth.Use(adminAllow.Middleware())
	{
		adminAuth.POST("/login", adminH.Login)
	}

	adminRead := r.Group("/api/admin")
	adminRead.Use(middleware.Limit(adminAPILimiter, "admin-api"))
	adminRead.Use(adminAllow.Middleware())
	adminRead.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.ResolveAdminIdentity))
	{
		adminRead.GET("/profile", adminH.Profile)
		// 改自己的密码与双因素设置不涉及他人，放在只读组，审计角色也能操作。
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
