package middleware

import (
	"sync"
	"time"
)

// LoginGuard 按「账号」维度限制连续登录失败。
//
// 为什么 IP 限流不够：攻击者可以用代理池 / 肉鸡，从成千上万个 IP 对**同一个账号**
// 做慢速爆破，此时按 IP 计数的令牌桶完全失效。这里以账号为键做指数退避锁定，
// 与 IP 限流形成互补：IP 限流挡高频单点，账号锁定挡分布式慢速撞库。
type LoginGuard struct {
	mu       sync.Mutex
	records  map[string]*failureRecord
	threshold int
	baseLock  time.Duration
	maxLock   time.Duration
}

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

// Check 判断该账号当前是否允许尝试登录。返回剩余锁定时长。
func (g *LoginGuard) Check(scope, account string) (bool, time.Duration) {
	key := scope + "|" + account
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
func (g *LoginGuard) Fail(scope, account string) {
	key := scope + "|" + account
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

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
func (g *LoginGuard) Reset(scope, account string) {
	key := scope + "|" + account
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.records, key)
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
