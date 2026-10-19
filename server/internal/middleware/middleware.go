package middleware

import (
	"container/list"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

const (
	CtxUserID     = "lt_user_id"
	CtxUsername   = "lt_username"
	CtxAdminID    = "lt_admin_id"
	CtxAdminRole  = "lt_admin_role"
	CtxAdminName  = "lt_admin_name"
	CtxAuthMethod = "lt_auth_method"
	CtxSessionID  = "lt_session_id"
)

const (
	AuthMethodSession    = "session"
	AuthMethodCredential = "credential"
)

func RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString(CtxAuthMethod) == AuthMethodCredential {
			httpx.Forbidden(c, "该操作需要使用登录会话，API Key 无权执行账号安全相关操作")
			return
		}
		c.Next()
	}
}

const MaxRequestBodyBytes = 1 << 20

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

const MultipartOverheadBytes = 1 << 20

func LimitBodySize(limit int64) gin.HandlerFunc {
	return LimitBodySizeFor(limit, nil)
}

func LimitBodySizeFor(fallback int64, routes map[string]int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := fallback
		if v, ok := routes[c.Request.Method+" "+c.Request.URL.Path]; ok {
			limit = v
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

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

type bucket struct {
	tokens   float64
	lastSeen time.Time
	elem     *list.Element
}

const maxBuckets = 50000

type RateSource func() (rate, capacity float64)

const limiterShardCount = 16

type rateShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	lru     *list.List
	maxSize int

	lastGC time.Time
}

func newRateShard(maxSize int) *rateShard {
	return &rateShard{
		buckets: make(map[string]*bucket),
		lru:     list.New(),
		maxSize: maxSize,
		lastGC:  time.Now(),
	}
}

type RateLimiter struct {
	shards  []*rateShard
	mask    uint64
	maxSize int

	evicted  atomic.Uint64
	warnMu   sync.Mutex
	lastWarn time.Time

	rate     float64
	capacity float64
	source   RateSource
}

func NewRateLimiter(rate, capacity float64) *RateLimiter {
	return newShardedRateLimiter(limiterShardCount, maxBuckets, nil, rate, capacity)
}

func NewDynamicRateLimiter(source RateSource) *RateLimiter {
	return newShardedRateLimiter(limiterShardCount, maxBuckets, source, 0, 0)
}

func newShardedRateLimiter(shards, maxSize int, source RateSource, rate, capacity float64) *RateLimiter {
	if maxSize <= 0 {
		maxSize = maxBuckets
	}
	if shards < 1 {
		shards = 1
	}
	for shards&(shards-1) != 0 {
		shards &= shards - 1
	}
	for shards > 1 && maxSize/shards == 0 {
		shards >>= 1
	}

	base, rem := maxSize/shards, maxSize%shards
	rl := &RateLimiter{
		shards:   make([]*rateShard, shards),
		mask:     uint64(shards - 1),
		maxSize:  maxSize,
		rate:     rate,
		capacity: capacity,
		source:   source,
	}
	for i := range rl.shards {
		size := base
		if i < rem {
			size++
		}
		rl.shards[i] = newRateShard(size)
	}
	registerRateLimiter(rl)
	return rl
}

func (rl *RateLimiter) shardFor(key string) *rateShard {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return rl.shards[h&rl.mask]
}

var limiterRegistry struct {
	mu    sync.Mutex
	items map[*RateLimiter]struct{}
}

func registerRateLimiter(rl *RateLimiter) {
	limiterRegistry.mu.Lock()
	if limiterRegistry.items == nil {
		limiterRegistry.items = make(map[*RateLimiter]struct{})
	}
	limiterRegistry.items[rl] = struct{}{}
	limiterRegistry.mu.Unlock()
}

func SweepIdleLimiters() {
	limiterRegistry.mu.Lock()
	limiters := make([]*RateLimiter, 0, len(limiterRegistry.items))
	for rl := range limiterRegistry.items {
		limiters = append(limiters, rl)
	}
	limiterRegistry.mu.Unlock()

	cutoff := time.Now().Add(-rateLimiterIdleTTL)
	for _, rl := range limiters {
		rl.dropIdle(cutoff)
	}
}

const (
	rateLimiterGCInterval = 10 * time.Minute
	rateLimiterIdleTTL    = 30 * time.Minute
)

func (rl *RateLimiter) limits() (rate, capacity float64) {
	if rl.source == nil {
		return rl.rate, rl.capacity
	}
	rate, capacity = rl.source()
	if rate <= 0 {
		rate = 0.05
	}
	if capacity < 1 {
		capacity = 1
	}
	return rate, capacity
}

func (rl *RateLimiter) dropIdle(cutoff time.Time) {
	for _, sh := range rl.shards {
		sh.mu.Lock()
		sh.dropIdleLocked(cutoff)
		sh.mu.Unlock()
	}
}

func (sh *rateShard) dropIdleLocked(cutoff time.Time) {
	for k, b := range sh.buckets {
		if b.lastSeen.Before(cutoff) {
			if b.elem != nil {
				sh.lru.Remove(b.elem)
			}
			delete(sh.buckets, k)
		}
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	allowed, warn := rl.allow(key)
	if warn != "" {
		log.Print(warn)
	}
	return allowed
}

func (rl *RateLimiter) allow(key string) (allowed bool, warn string) {
	rate, capacity := rl.limits()

	sh := rl.shardFor(key)
	allowed, evicted := sh.allow(key, time.Now(), rate, capacity)
	if evicted == 0 {
		return allowed, ""
	}
	return allowed, rl.warnMessage(rl.evicted.Add(evicted))
}

func (sh *rateShard) allow(key string, now time.Time, rate, capacity float64) (allowed bool, evicted uint64) {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if now.Sub(sh.lastGC) >= rateLimiterGCInterval {
		sh.lastGC = now
		sh.dropIdleLocked(now.Add(-rateLimiterIdleTTL))
	}

	b, ok := sh.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity - 1, lastSeen: now}
		b.elem = sh.lru.PushBack(key)
		sh.buckets[key] = b
		return true, sh.evictLocked()
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(capacity, b.tokens+elapsed*rate)
	b.lastSeen = now
	if b.elem != nil {
		sh.lru.MoveToBack(b.elem)
	}
	if b.tokens < 1 {
		return false, 0
	}
	b.tokens--
	return true, 0
}

func (sh *rateShard) evictLocked() uint64 {
	var evicted uint64
	for len(sh.buckets) > sh.maxSize {
		oldest := sh.lru.Front()
		if oldest == nil {
			break
		}
		key, _ := oldest.Value.(string)
		sh.lru.Remove(oldest)
		delete(sh.buckets, key)
		evicted++
	}
	return evicted
}

func (rl *RateLimiter) warnMessage(evicted uint64) string {
	rl.warnMu.Lock()
	defer rl.warnMu.Unlock()
	if evicted == 0 || time.Since(rl.lastWarn) < time.Minute {
		return ""
	}
	rl.lastWarn = time.Now()
	return fmt.Sprintf(
		"[limit] 令牌桶已达上限 %d（分片 %d 个），累计淘汰 %d 个最久未用的桶：可能存在大量分散来源的请求，建议在入口反代再加一层限流",
		rl.maxSize, len(rl.shards), evicted)
}

func Limit(rl *RateLimiter, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := scope + "|" + c.ClientIP()
		if !rl.Allow(key) {
			httpx.Fail(c, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
			return
		}
		c.Next()
	}
}

type IdentityResolver func(id uint) (active bool, tokenVersion int)

func extractToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	after, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(after)
}

func checkIdentity(c *gin.Context, resolve IdentityResolver, id uint, claimVersion int) bool {
	if resolve == nil {
		return true
	}
	active, current := resolve(id)
	if !active {
		httpx.Unauthorized(c, "账号已被禁用或不存在，请重新登录")
		return false
	}
	if current != claimVersion {
		httpx.Unauthorized(c, "登录状态已失效（密码已变更），请重新登录")
		return false
	}
	return true
}

func checkActiveOnly(c *gin.Context, resolve IdentityResolver, id uint) bool {
	if resolve == nil {
		return true
	}
	active, _ := resolve(id)
	if !active {
		httpx.Unauthorized(c, "账号已被禁用或不存在，请重新登录")
		return false
	}
	return true
}

func UserAuth(secret string, resolve IdentityResolver) gin.HandlerFunc {
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
		if !checkIdentity(c, resolve, claims.UserID, claims.Version) {
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxUsername, claims.Username)
		c.Set(CtxAuthMethod, AuthMethodSession)
		c.Next()
	}
}

func ReadOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
		default:
			httpx.Forbidden(c, "该接口组仅支持读取")
		}
	}
}

func AdminAuth(secret string, resolve IdentityResolver, allowRoles ...string) gin.HandlerFunc {
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
		if !checkIdentity(c, resolve, claims.UserID, claims.Version) {
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
		// 本项目的管理员会话就是一枚 JWT，没有服务端会话表；
		// 用签发时间当会话标识，同一次登录拿到的令牌共享一个 step-up 授权。
		if claims.IssuedAt != nil {
			c.Set(CtxSessionID, strconv.FormatInt(claims.IssuedAt.Unix(), 10))
		}
		c.Next()
	}
}

type CredentialResolver func(plain string) (userID uint, username string, err error)

func UserAuthFlexible(secret string, resolve CredentialResolver, status IdentityResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}

		if claims, err := auth.Parse(secret, auth.DomainUser, tokenStr); err == nil {
			if !checkIdentity(c, status, claims.UserID, claims.Version) {
				return
			}
			c.Set(CtxUserID, claims.UserID)
			c.Set(CtxUsername, claims.Username)
			c.Set(CtxAuthMethod, AuthMethodSession)
			c.Next()
			return
		}

		if resolve != nil {
			if uid, uname, err := resolve(tokenStr); err == nil {
				if !checkActiveOnly(c, status, uid) {
					return
				}
				c.Set(CtxUserID, uid)
				c.Set(CtxUsername, uname)
				c.Set(CtxAuthMethod, AuthMethodCredential)
				c.Next()
				return
			}
		}

		httpx.Unauthorized(c, "身份校验失败，请重新登录或检查 API Key")
	}
}

func CurrentUserID(c *gin.Context) uint {
	v, _ := c.Get(CtxUserID)
	id, _ := v.(uint)
	return id
}

func CurrentAdminID(c *gin.Context) (uint, string, string) {
	idV, _ := c.Get(CtxAdminID)
	nameV, _ := c.Get(CtxAdminName)
	roleV, _ := c.Get(CtxAdminRole)
	id, _ := idV.(uint)
	name, _ := nameV.(string)
	role, _ := roleV.(string)
	return id, name, role
}
