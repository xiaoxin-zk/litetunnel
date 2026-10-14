// Package middleware 提供安全头、限流与双域鉴权中间件。
package middleware

import (
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// 上下文键
const (
	CtxUserID   = "lt_user_id"
	CtxUsername = "lt_username"
	CtxAdminID  = "lt_admin_id"
	CtxAdminRole = "lt_admin_role"
	CtxAdminName = "lt_admin_name"
)

// SecurityHeaders 注入基础安全响应头。
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		c.Next()
	}
}

// CORSDevOnly 仅在开发环境放开跨域，生产环境两个控制台由本服务同源提供，无需 CORS。
func CORSDevOnly(isProd bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isProd {
			origin := c.GetHeader("Origin")
			if origin != "" {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Requested-With")
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			}
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
		}
		c.Next()
	}
}

// ---- 限流 ----

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// RateLimiter 基于令牌桶的内存限流器，按 IP + 分组键隔离。
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // 每秒补充令牌数
	capacity float64
}

// NewRateLimiter 创建限流器：每秒补充 rate 个令牌，桶容量 capacity。
func NewRateLimiter(rate, capacity float64) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		capacity: capacity,
	}
	go rl.gc()
	return rl
}

func (rl *RateLimiter) gc() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-30 * time.Minute)
		rl.mu.Lock()
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow 判断某键是否放行。
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(rl.capacity, b.tokens+elapsed*rl.rate)
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Limit 返回限流中间件。
func Limit(rl *RateLimiter, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := scope + "|" + c.ClientIP()
		if !rl.Allow(key) {
			httpx.Fail(c, 429, "请求过于频繁，请稍后再试")
			return
		}
		c.Next()
	}
}

// ---- 双域鉴权 ----

func extractToken(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	// 兜底：部分场景通过查询串传递（仅用于客户端下载等只读接口）
	return strings.TrimSpace(c.Query("token"))
}

// UserAuth 用户域鉴权：只接受用户域 JWT，管理域令牌在此处一定失败。
func UserAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}
		claims, err := auth.Parse(secret, auth.DomainUser, tokenStr)
		if err != nil {
			httpx.Unauthorized(c, "登录状态已失效，请重新登录")
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxUsername, claims.Username)
		c.Next()
	}
}

// AdminAuth 管理域鉴权：只接受管理域 JWT，且校验角色。
func AdminAuth(secret string, allowRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowRoles))
	for _, r := range allowRoles {
		allowed[r] = struct{}{}
	}
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}
		claims, err := auth.Parse(secret, auth.DomainAdmin, tokenStr)
		if err != nil {
			httpx.Unauthorized(c, "登录状态已失效，请重新登录")
			return
		}
		if len(allowed) > 0 {
			if _, ok := allowed[claims.Role]; !ok {
				httpx.Forbidden(c, "当前角色无此操作权限")
				return
			}
		}
		c.Set(CtxAdminID, claims.UserID)
		c.Set(CtxAdminName, claims.Username)
		c.Set(CtxAdminRole, claims.Role)
		c.Next()
	}
}

// APIKeyResolver 由上层注入，用于把 API Key 明文解析为身份。
// 通过函数注入而非直接依赖 service 包，避免中间件与业务层循环依赖。
type APIKeyResolver func(plain string) (userID uint, username string, err error)

// UserAuthFlexible 允许用户域 JWT 或 API Key 二选一通过。
// 供桌面客户端使用：客户端只持有 API Key，不需要登录会话。
func UserAuthFlexible(secret string, resolve APIKeyResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}

		// 优先按 JWT 解析；失败再交给上层解析 API Key 或客户端凭据。
		if claims, err := auth.Parse(secret, auth.DomainUser, tokenStr); err == nil {
			c.Set(CtxUserID, claims.UserID)
			c.Set(CtxUsername, claims.Username)
			c.Next()
			return
		}

		if resolve != nil {
			if uid, uname, err := resolve(tokenStr); err == nil {
				c.Set(CtxUserID, uid)
				c.Set(CtxUsername, uname)
				c.Next()
				return
			}
		}

		httpx.Unauthorized(c, "身份校验失败，请重新登录或检查 API Key")
	}
}

// CurrentUserID 从上下文取用户 ID。
func CurrentUserID(c *gin.Context) uint {
	v, _ := c.Get(CtxUserID)
	id, _ := v.(uint)
	return id
}

// CurrentAdminID 从上下文取管理员 ID 与名称。
func CurrentAdminID(c *gin.Context) (uint, string, string) {
	idV, _ := c.Get(CtxAdminID)
	nameV, _ := c.Get(CtxAdminName)
	roleV, _ := c.Get(CtxAdminRole)
	id, _ := idV.(uint)
	name, _ := nameV.(string)
	role, _ := roleV.(string)
	return id, name, role
}
