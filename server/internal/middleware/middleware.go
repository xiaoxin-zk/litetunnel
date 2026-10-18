// Package middleware 提供安全头、限流、请求体限制与双域鉴权中间件。
package middleware

import (
	"container/list"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// 上下文键
const (
	CtxUserID    = "lt_user_id"
	CtxUsername  = "lt_username"
	CtxAdminID   = "lt_admin_id"
	CtxAdminRole = "lt_admin_role"
	CtxAdminName = "lt_admin_name"
	// CtxAuthMethod 标记本次请求用的是会话令牌还是长期凭据。
	CtxAuthMethod = "lt_auth_method"
)

// 认证方式。
const (
	// AuthMethodSession 是浏览器会话令牌（JWT），可执行全部操作。
	AuthMethodSession = "session"
	// AuthMethodCredential 是长期凭据（API Key / 客户端接入凭据）。
	//
	// 这类凭据会以明文落在客户端本地的配置文件里，一旦泄露不应等价于
	// 账号被完全接管，因此只允许访问只读接口。
	AuthMethodCredential = "credential"
)

// RequireSession 要求本次请求使用会话令牌，拒绝长期凭据。
//
// 为什么必须加这一层：API Key 会以明文落在客户端本地配置文件里。
// 让它可以「使用账号」（读写隧道、兑换）是必要的——那正是客户端存在的意义；
// 但不能让它「控制账号」——改密码、改邮箱、重置 API Key、注销账号
// 这些是账号接管的关键步骤，一旦泄露即不可逆。
//
// 换句话说：一把可能泄露的钥匙，允许它开门，不允许它换锁。
//
// 返回 403 而不是 401：请求带的是**有效**凭据，只是没有这项权限。
// 401 的意思是「你没通过认证」，用它会让客户端误以为该重新登录。
func RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString(CtxAuthMethod) == AuthMethodCredential {
			httpx.Forbidden(c, "该操作需要使用登录会话，API Key 无权执行账号安全相关操作")
			return
		}
		c.Next()
	}
}

// MaxRequestBodyBytes 是单个请求体的上限。
// 不做限制时，攻击者可以用超大 JSON 耗尽内存。
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

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

// MultipartOverheadBytes 是 multipart 请求里给表头与 boundary 预留的余量。
//
// 上传安装包时，请求体不只有文件本身：还有 boundary、每段的头部、以及可能的
// 其它表单字段。上限卡在「文件大小」这个数上，会让一个刚好等于上限的文件因为
// 多出来的几十个字节被拒——错误还是「请求体过大」，与真正的原因差得很远。
const MultipartOverheadBytes = 1 << 20

// LimitBodySize 限制请求体大小，防止内存耗尽型攻击。
func LimitBodySize(limit int64) gin.HandlerFunc {
	return LimitBodySizeFor(limit, nil)
}

// LimitBodySizeFor 是带例外的请求体上限：routes 的键是 "METHOD 路径"（精确
// 匹配 URL.Path），命中时用它的上限，其余请求仍走 fallback。
//
// 为什么需要例外：安装包上传是几十 MB，而全局 1 MiB 会在读取 FormFile 时
// 直接失败——一个功能被一条与本意无关的通用限制悄悄关掉，而且报错看起来
// 像「请求格式不对」。反过来把全局上限抬高更糟：那等于让每个 JSON 接口
// 都能收几十 MB。
//
// 刻意用精确路径而不是前缀/通配：哪些接口可以收大包必须是一条能被读出来的
// 清单，而不是一条需要推断的规则。
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
	// elem 是桶在 LRU 链表中的位置，用于容量满时定位最久未用的桶。
	elem *list.Element
}

// maxBuckets 是**单个**限流器保留的令牌桶数量上限。
//
// 没有上限时，攻击者用大量分散来源的请求就能让这张表无限增长：GC 只清理
// 30 分钟无活动的桶，而攻击者只要持续换 IP 就能一直制造新桶。
//
// 取值说明：每个桶连同 map 与键的开销约两三百字节，5 万个桶约十几 MB。
// 取 maxLoginRecords 的一半，是因为路由里同时存在四个限流器实例
// （登录、用户接口、管理接口、用户认证各一个），这样「所有实例加起来」
// 的总量级仍与 LoginGuard 单表相当。分散来源的正常流量远达不到这个规模，
// 达到就说明该在入口反代再加一层限流了。
const maxBuckets = 50000

// RateSource 返回当前的「每秒补充令牌数」与「桶容量」。
// 由上层注入，使限流阈值可以在管理端热调整而无需重启。
type RateSource func() (rate, capacity float64)

// RateLimiter 基于令牌桶的内存限流器，按 IP + 分组键隔离。
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	// lru 按「最近使用」排序，Front 是最久未用的桶。
	//
	// 存在的意义只有一个：容量满时能 O(1) 找到该淘汰谁。用扫描找最久未用
	// 的桶是不行的——容量满恰恰只在攻击期间发生，那时每次插入都扫一遍，
	// 等于把内存问题换成了 CPU 问题。
	lru     *list.List
	maxSize int

	evicted  uint64    // 累计淘汰数，用于告警
	lastWarn time.Time // 上次告警时间，避免日志被洪水放大

	// lastGC 是上一次清理空闲桶的时刻。清理写在请求路径上（见 allow），
	// 不再单独起 gc 协程：那个协程没有关闭入口，每个限流器实例都会留下
	// 一个永不退出的 goroutine（路由每重建一次就多一个，测试里尤其明显）。
	lastGC time.Time

	rate     float64 // 每秒补充令牌数
	capacity float64
	// source 非空时改用实时读取的阈值，用于支持管理端热调整。
	source RateSource
}

// NewRateLimiter 创建限流器：每秒补充 rate 个令牌，桶容量 capacity。
func NewRateLimiter(rate, capacity float64) *RateLimiter {
	return newRateLimiter(maxBuckets, nil, rate, capacity)
}

// NewDynamicRateLimiter 创建阈值可热调整的限流器。
//
// 刻意不在配置变更时重建限流器：重建会清空所有令牌桶，
// 攻击者只要设法让管理员改一次配置，就能顺带重置自己的配额。
// 这里保持桶本身不变，仅在补充令牌时采用最新速率。
func NewDynamicRateLimiter(source RateSource) *RateLimiter {
	return newRateLimiter(maxBuckets, source, 0, 0)
}

func newRateLimiter(maxSize int, source RateSource, rate, capacity float64) *RateLimiter {
	if maxSize <= 0 {
		maxSize = maxBuckets
	}
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		lru:      list.New(),
		maxSize:  maxSize,
		rate:     rate,
		capacity: capacity,
		source:   source,
		lastGC:   time.Now(),
	}
	registerRateLimiter(rl)
	return rl
}

// limiterRegistry 记录进程内创建的限流器，供维护任务统一清扫空闲桶。
//
// 限流器由路由层创建，而路由层没有关闭入口（router.New 返回 *gin.Engine），
// 所以「还有哪些实例活着」只能在这里登记。条目只在进程生命周期内存在：
// 路由重建一般只发生在测试里，进程结束一并消失。
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

// SweepIdleLimiters 立即清理所有限流器的空闲桶。
//
// 请求路径上的惰性清理只在有流量时触发。流量退潮之后再没有请求的实例
// （例如只服务某个默认端口的限流器）会把峰值数量的桶一直留着；周期维护
// 任务调这里兜底，不必为每个实例起一个 gc 协程。
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
	// rateLimiterGCInterval 是两次空闲桶清理之间的最小间隔。
	rateLimiterGCInterval = 10 * time.Minute
	// rateLimiterIdleTTL 是桶无活动多久后可回收。
	rateLimiterIdleTTL = 30 * time.Minute
)

// limits 返回本次使用的速率与容量，并做兜底，避免配置异常导致完全放开。
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

// dropIdle 清理超过 cutoff 未活动的桶。
func (rl *RateLimiter) dropIdle(cutoff time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.dropIdleLocked(cutoff)
}

// dropIdleLocked 是 dropIdle 的主体。调用方必须持有 rl.mu。
//
// 摘链与删表必须成对：只删 map 不摘链，链表会残留已不存在的键，
// 容量满时淘汰到的是一个空壳——表现为「桶数没到上限却一直在淘汰」。
func (rl *RateLimiter) dropIdleLocked(cutoff time.Time) {
	for k, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			if b.elem != nil {
				rl.lru.Remove(b.elem)
			}
			delete(rl.buckets, k)
		}
	}
}

// Allow 判断某键是否放行。
func (rl *RateLimiter) Allow(key string) bool {
	allowed, warn := rl.allow(key)
	// 告警在锁外打印：日志写入可能阻塞（管道、慢盘），
	// 不该让所有请求排在它后面。
	if warn != "" {
		log.Print(warn)
	}
	return allowed
}

// allow 是 Allow 的主体，返回「是否放行」与「需要打印的告警」。
func (rl *RateLimiter) allow(key string) (allowed bool, warn string) {
	rate, capacity := rl.limits()

	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// 空闲桶清理写在请求路径上：限流器只服务于流量，没有请求时也不会
	// 产生新桶，本来就没有需要回收的东西。间隔判定保证它不会每个请求都扫。
	if now.Sub(rl.lastGC) >= rateLimiterGCInterval {
		rl.lastGC = now
		rl.dropIdleLocked(now.Add(-rateLimiterIdleTTL))
	}

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity - 1, lastSeen: now}
		b.elem = rl.lru.PushBack(key)
		rl.buckets[key] = b
		return true, rl.evictLocked()
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(capacity, b.tokens+elapsed*rate)
	b.lastSeen = now
	// 空判是防御性的：elem 为 nil 说明这个桶不是经由本方法建的
	// （目前没有这种路径）。真出现时也只是一次位置更新被跳过，
	// 而不是在这里 panic —— 限流器 panic 等于每个请求都 500。
	if b.elem != nil {
		rl.lru.MoveToBack(b.elem)
	}
	if b.tokens < 1 {
		return false, ""
	}
	b.tokens--
	return true, ""
}

// evictLocked 在超出容量上限时淘汰最久未用的桶，返回需要打印的告警（无则空串）。
//
// # 为什么淘汰最久未用的，而不是像 LoginGuard 那样整表清空
//
// 限流器的桶里装的是**剩余配额**。整表清空等于给所有来源一次性发满令牌，
// 而触发清空的恰恰是攻击流量——也就是在攻击者最需要额度的时候把闸门打开。
// 只淘汰最久未用的，活跃来源的配额不受影响；被淘汰的那部分来源会重新开始
// 计数，这是容量受限下必然要付出的代价，但不会变成一次集体放行。
func (rl *RateLimiter) evictLocked() string {
	for len(rl.buckets) > rl.maxSize {
		oldest := rl.lru.Front()
		if oldest == nil {
			break
		}
		key, _ := oldest.Value.(string)
		rl.lru.Remove(oldest)
		delete(rl.buckets, key)
		rl.evicted++
	}
	// 限频告警：淘汰一开始就意味着「有大量分散来源」，
	// 但洪水期间每次插入都会触发，不加限频日志本身会成为放大器。
	if rl.evicted == 0 || time.Since(rl.lastWarn) < time.Minute {
		return ""
	}
	rl.lastWarn = time.Now()
	return fmt.Sprintf(
		"[limit] 令牌桶已达上限 %d，累计淘汰 %d 个最久未用的桶：可能存在大量分散来源的请求，建议在入口反代再加一层限流",
		rl.maxSize, rl.evicted)
}

// Limit 返回限流中间件。
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

// ---- 双域鉴权 ----

// IdentityResolver 由上层注入，用于在每次请求时确认主体的实时状态。
//
// 仅校验 JWT 签名是不够的：JWT 无状态，账号被禁用或密码被重置后，
// 已签发的令牌在有效期内依然能通过签名校验。
// 返回的 tokenVersion 会与令牌中的声明比对，从而实现「改密即全端下线」。
type IdentityResolver func(id uint) (active bool, tokenVersion int)

// extractToken 只从 Authorization 头读取令牌。
//
// 刻意不支持 ?token= 查询参数：URL 会进入访问日志、Referer 与浏览器历史，
// 等同于把凭据明文写入日志。
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

// checkIdentity 统一处理「签名有效但主体状态已变化」的情况。
//
// 用于 JWT 路径：既校验账号有效，也校验令牌版本（实现「改密即全端下线」）。
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

// checkActiveOnly 只校验账号是否仍然有效，不做令牌版本比对。
//
// 用于长期凭据路径（API Key / 客户端接入凭据）：这类凭据本身不带版本号，
// 若强行与账号版本比对，会因为「凭据没有版本」而恒不相等，导致全部被拒。
//
// 关于「改密后旧凭据是否还有效」——这是刻意的设计取舍，不是遗漏：
//   - 用户自助改密（知道原密码）：保留长期凭据，避免每次改密都要重新配置客户端；
//   - 邮件找回密码 / 管理员重置：属于账号可能已被他人控制的场景，
//     会一并轮换 client_secret（见 ResetPassword），旧客户端配置立即失效；
//   - API Key 需要单独吊销：控制台「API Key → 重置」。
//
// 也就是说长期凭据与登录会话是两套独立的吊销通道，这与其他主流平台
// （GitHub PAT、AWS Access Key）的语义一致。
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

// UserAuth 用户域鉴权：只接受用户域 JWT，管理域令牌在此处一定失败。
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

// ReadOnly 只允许读取类方法，拒绝其他 HTTP 方法。
//
// 用于「长期凭据可访问」的路由组。这一层不是为了当下的安全，
// 而是为了防止以后有人往这个组里加了一个写接口——那样 API Key
// 就会在无人察觉的情况下获得写权限。有了它，加错了也写不进去。
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

// AdminAuth 管理域鉴权：只接受管理域 JWT，且校验角色。
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
		// 角色以令牌为准，但账号是否仍然启用、令牌版本是否一致必须实时查证。
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
		c.Next()
	}
}

// CredentialResolver 由上层注入，把 API Key 或客户端接入凭据解析为身份。
// 通过函数注入而非直接依赖 service 包，避免中间件与业务层循环依赖。
type CredentialResolver func(plain string) (userID uint, username string, err error)

// UserAuthFlexible 允许用户域 JWT 或长期凭据（API Key / 客户端接入凭据）通过。
// 供桌面客户端使用：客户端只持有凭据，不需要登录会话。
func UserAuthFlexible(secret string, resolve CredentialResolver, status IdentityResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}

		// 优先按 JWT 解析；失败再交给上层解析长期凭据。
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

		// 长期凭据（API Key / 客户端接入凭据）不携带令牌版本，
		// 因此只校验账号是否仍然有效，不做版本比对。
		if resolve != nil {
			if uid, uname, err := resolve(tokenStr); err == nil {
				if !checkActiveOnly(c, status, uid) {
					return
				}
				c.Set(CtxUserID, uid)
				c.Set(CtxUsername, uname)
				// 标记为长期凭据：写操作会被 RequireSession 拒绝。
				c.Set(CtxAuthMethod, AuthMethodCredential)
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

// CurrentAdminID 从上下文取管理员 ID、名称与角色。
func CurrentAdminID(c *gin.Context) (uint, string, string) {
	idV, _ := c.Get(CtxAdminID)
	nameV, _ := c.Get(CtxAdminName)
	roleV, _ := c.Get(CtxAdminRole)
	id, _ := idV.(uint)
	name, _ := nameV.(string)
	role, _ := roleV.(string)
	return id, name, role
}
