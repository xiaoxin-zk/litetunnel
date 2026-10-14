package middleware

import (
	"strings"
	"sync"
	"time"
)

// LoginGuard 按「账号 + 来源 IP」维度限制连续登录失败。
//
// 为什么不是纯 IP 限流：攻击者可以用代理池 / 肉鸡，从成千上万个 IP 对**同一个账号**
// 做慢速爆破，此时按 IP 计数的令牌桶完全失效。
//
// 为什么也不是纯账号锁定：那会变成一个廉价的拒绝服务——
// 攻击者只要知道管理员用户名，每隔一段时间发几次错误密码，
// 就能让管理员**永远无法登录**。账号锁定维度越粗，被武器化的代价越低。
//
// 折中方案：硬锁按「账号 + IP」计数。攻击者只能锁住自己那个 IP；
// 而针对单一账号的分布式爆破，由「账号累计失败达阈值后要求验证码」来兜底
// （见 service.CaptchaRequired），验证码不需要硬锁也能挡住脚本。
//
// 记录只存内存：重启即清空，这是可接受的——重启本身就是一次人工介入。
type LoginGuard struct {
	mu        sync.Mutex
	records   map[string]*failureRecord
	threshold int
	baseLock  time.Duration
	maxLock   time.Duration
}

// maxLoginRecords 是失败记录表的容量上限。
//
// 没有上限时，攻击者用**随机用户名**持续制造失败记录，可以让这张表无限增长：
// GC 只清理 2 小时无活动的记录，而攻击者只要周期性再失败一次就能让它一直存活。
const maxLoginRecords = 100000

type failureRecord struct {
	count      int
	lockedTill time.Time
	lastFail   time.Time
}

// NewLoginGuard 构造账号锁定器。
//
//	threshold 连续失败多少次后开始锁定
//	baseLock  首次锁定时长，之后按次数翻倍
//	maxLock   单次锁定上限
func NewLoginGuard(threshold int, baseLock, maxLock time.Duration) *LoginGuard {
	if threshold < 1 {
		threshold = 5
	}
	if baseLock <= 0 {
		baseLock = 15 * time.Minute
	}
	if maxLock <= 0 {
		maxLock = 24 * time.Hour
	}
	g := &LoginGuard{
		records:   make(map[string]*failureRecord),
		threshold: threshold,
		baseLock:  baseLock,
		maxLock:   maxLock,
	}
	go g.gc()
	return g
}

// guardKey 组合锁定维度：作用域 + 账号 + 来源 IP。
//
// 账号做小写归一化：登录本身不区分大小写，若不归一化，
// 攻击者用 Admin / ADMIN / aDmin 就能绕过同一个账号的失败计数。
func guardKey(scope, account, ip string) string {
	return scope + "|" + strings.ToLower(strings.TrimSpace(account)) + "|" + ip
}

// Check 判断该账号 + IP 当前是否允许尝试登录。返回剩余锁定时长。
func (g *LoginGuard) Check(scope, account, ip string) (bool, time.Duration) {
	key := guardKey(scope, account, ip)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	rec, ok := g.records[key]
	if !ok {
		return true, 0
	}
	if now.Before(rec.lockedTill) {
		return false, rec.lockedTill.Sub(now)
	}
	return true, 0
}

// Fail 记录一次失败，必要时升级为锁定。
func (g *LoginGuard) Fail(scope, account, ip string) {
	key := guardKey(scope, account, ip)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	// 容量保护：达到上限时整表清空。
	// 宁可让少数攻击者重新开始计数，也不让内存被随机用户名撑爆。
	if len(g.records) >= maxLoginRecords {
		g.records = make(map[string]*failureRecord)
	}

	rec, ok := g.records[key]
	if !ok {
		rec = &failureRecord{}
		g.records[key] = rec
	}
	rec.count++
	rec.lastFail = now

	if rec.count >= g.threshold {
		// 指数退避：第 threshold 次锁 baseLock，之后逐次翻倍直到上限。
		over := rec.count - g.threshold
		if over > 20 {
			over = 20 // 防止移位溢出
		}
		lock := g.baseLock << uint(over)
		if lock <= 0 || lock > g.maxLock {
			lock = g.maxLock
		}
		rec.lockedTill = now.Add(lock)
	}
}

// Reset 登录成功后清除失败记录。
func (g *LoginGuard) Reset(scope, account, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.records, guardKey(scope, account, ip))
}

// gc 定期清理已解锁且长时间无活动的记录，避免内存无限增长。
func (g *LoginGuard) gc() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-2 * time.Hour)
		g.mu.Lock()
		for k, rec := range g.records {
			if rec.lastFail.Before(cutoff) && time.Now().After(rec.lockedTill) {
				delete(g.records, k)
			}
		}
		g.mu.Unlock()
	}
}
