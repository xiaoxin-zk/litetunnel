// Package router 组装用户侧与管理侧两套互相隔离的路由。
//
// 隔离策略（三重）：
//  1. 网络层：用户侧监听 0.0.0.0，管理侧默认只监听 127.0.0.1，物理端口不同；
//  2. 令牌层：两套 JWT 使用不同密钥且 aud 不同，令牌无法跨域使用；
//  3. 路由层：管理路由只注册在管理侧引擎上，公网端口不存在该路径。
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

// newEngine 创建带通用中间件的引擎。
func newEngine(cfg *config.Config) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.LimitBodySize(middleware.MaxRequestBodyBytes))
	r.Use(middleware.CORSDevOnly(cfg.IsProd()))
	// 只信任反代地址的转发头，防止客户端伪造来源 IP 绕过限流与白名单。
	_ = r.SetTrustedProxies(cfg.TrustedProxies)
	return r
}

// NewUser 构建用户控制台路由。
func NewUser(cfg *config.Config, svc *service.Services, h *userapi.Handler) *gin.Engine {
	r := newEngine(cfg)
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 登录/注册类接口用更严格的限流，抵御撞库。
	authLimiter := middleware.NewRateLimiter(0.5, 10)
	apiLimiter := middleware.NewRateLimiter(30, 90)

	auth := r.Group("/api/user/auth")
	auth.Use(middleware.Limit(authLimiter, "user-auth"))
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
	}

	// 桌面客户端接入：同样是密码校验入口，必须同样限流 + 账号锁定。
	clientPub := r.Group("/api/user/client")
	clientPub.Use(middleware.Limit(authLimiter, "user-client-auth"))
	{
		clientPub.POST("/auth", h.ClientAuth)
	}

	// 桌面客户端接口：支持 JWT 或长期凭据（API Key / 客户端接入凭据）。
	cli := r.Group("/api/user/client")
	cli.Use(middleware.Limit(apiLimiter, "user-client"))
	cli.Use(middleware.UserAuthFlexible(cfg.UserJWTSecret, svc.ResolveCredential, svc.IsActiveUser))
	{
		cli.GET("/info", h.ClientInfo)
		cli.GET("/config", h.ClientConfig)
		cli.GET("/downloads", h.ClientDownloads)
		cli.GET("/downloads/:name", h.ClientDownloadFile)
	}

	// 用户控制台接口：只接受用户域 JWT。
	api := r.Group("/api/user")
	api.Use(middleware.Limit(apiLimiter, "user-api"))
	api.Use(middleware.UserAuth(cfg.UserJWTSecret, svc.IsActiveUser))
	{
		api.GET("/profile", h.Profile)
		api.POST("/logout", h.Logout)
		api.PUT("/profile/password", h.ChangePassword)

		api.GET("/tunnels", h.ListTunnels)
		api.POST("/tunnels", h.CreateTunnel)
		api.PUT("/tunnels/:id", h.UpdateTunnel)
		api.DELETE("/tunnels/:id", h.DeleteTunnel)
		api.POST("/tunnels/:id/status", h.SetTunnelStatus)

		api.GET("/apikey", h.GetAPIKey)
		api.POST("/apikey/reveal", h.RevealAPIKey)
		api.POST("/apikey/rotate", h.RotateAPIKey)

		api.POST("/redeem", h.Redeem)
		api.GET("/redeem/records", h.RedeemRecords)

		api.GET("/stats/overview", h.StatsOverview)
		api.GET("/stats/traffic", h.TrafficStats)
	}

	serveSPA(r, cfg.UserWebDir, "/api/")
	return r
}

// NewAdmin 构建管理后台路由。
func NewAdmin(cfg *config.Config, svc *service.Services, h *adminapi.Handler, plugin *frpsplugin.Handler) *gin.Engine {
	r := newEngine(cfg)
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// frps 服务端插件回调：仅允许受信网段访问。
	r.POST("/api/frps/plugin", plugin.Guard(), plugin.Handle)

	authLimiter := middleware.NewRateLimiter(0.2, 5)
	apiLimiter := middleware.NewRateLimiter(30, 90)

	auth := r.Group("/api/admin/auth")
	auth.Use(middleware.Limit(authLimiter, "admin-auth"))
	{
		auth.POST("/login", h.Login)
	}

	api := r.Group("/api/admin")
	api.Use(middleware.Limit(apiLimiter, "admin-api"))
	api.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.IsActiveAdmin))
	{
		api.GET("/profile", h.Profile)
		// 改自己的密码不涉及他人，放在只读组，审计角色也能操作。
		api.PUT("/profile/password", h.ChangePassword)
		api.GET("/stats/overview", h.StatsOverview)

		api.GET("/users", h.ListUsers)
		api.GET("/groups", h.ListGroups)
		api.GET("/tunnels", h.ListTunnels)
		api.GET("/redeem-codes", h.ListRedeemCodes)
		api.GET("/redeem-records", h.ListRedeemRecords)
		api.GET("/clients", h.ListClients)
		api.GET("/audit-logs", h.ListAuditLogs)
	}

	// 写操作额外要求 super / operator 角色，auditor 只读。
	write := r.Group("/api/admin")
	write.Use(middleware.Limit(apiLimiter, "admin-write"))
	write.Use(middleware.AdminAuth(cfg.AdminJWTSecret, svc.IsActiveAdmin, "super", "operator"))
	{
		write.POST("/users", h.CreateUser)
		write.PUT("/users/:id", h.UpdateUser)
		write.DELETE("/users/:id", h.DeleteUser)
		write.POST("/users/:id/status", h.SetUserStatus)
		write.POST("/users/:id/quota", h.SetUserQuota)
		write.POST("/users/:id/traffic-reset", h.ResetUserTraffic)
		write.POST("/users/:id/group", h.SetUserGroup)
		write.POST("/users/:id/password", h.ResetUserPassword)
		write.POST("/users/:id/reset-secret", h.ResetUserSecret)

		write.POST("/groups", h.CreateGroup)
		write.PUT("/groups/:id", h.UpdateGroup)
		write.DELETE("/groups/:id", h.DeleteGroup)

		write.POST("/tunnels/:id/status", h.SetTunnelStatus)
		write.DELETE("/tunnels/:id", h.DeleteTunnel)

		write.POST("/redeem-codes/generate", h.GenerateRedeemCodes)
		write.POST("/redeem-codes/:id/status", h.SetRedeemCodeStatus)
		write.DELETE("/redeem-codes/:id", h.DeleteRedeemCode)
	}

	serveSPA(r, cfg.AdminWebDir, "/api/")
	return r
}

// serveSPA 托管前端单页应用。
//
// 目录不存在时静默跳过，服务以纯 API 模式运行（便于前后端分离开发）。
func serveSPA(r *gin.Engine, dir string, apiPrefix string) {
	if dir == "" {
		return
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return
	}

	index := filepath.Join(dir, "index.html")
	assets := filepath.Join(dir, "assets")
	if st, err := os.Stat(assets); err == nil && st.IsDir() {
		r.Static("/assets", assets)
	}

	r.NoRoute(func(c *gin.Context) {
		// API 路径不做 SPA 回退，避免把 404 伪装成 200 页面。
		if strings.HasPrefix(c.Request.URL.Path, apiPrefix) {
			httpx.NotFound(c, "接口不存在")
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			httpx.NotFound(c, "资源不存在")
			return
		}
		c.File(index)
	})
}
