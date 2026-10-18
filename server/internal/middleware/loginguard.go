package middleware

import (
	"log"
	"sort"
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

	// stop 用于结束 gc 协程。没有它，每次 NewLoginGuard 都会留下一个
	// 永不退出的协程——常驻进程里只是多一个 ticker，测试里则是每次
	// 建栈泄漏一个，长期跑下去 goroutine 数只增不减。
	stop chan struct{}
	// closeOnce 让 Close 可被重复调用（defer 里再叫一次也不会 panic）。
	closeOnce sync.Once
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
		stop:      make(chan struct{}),
	}
	go g.gc()
	return g
}

// Close 停止 gc 协程。
//
// 只终止后台清理，不动记录表：关闭之后记录仍可读，调用方不必区分
// 「已关闭」与「没有记录」——两者都不该影响任何一次判定。
func (g *LoginGuard) Close() {
	if g == nil {
		return
	}
	g.closeOnce.Do(func() { close(g.stop) })
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
	// 容量保护：按代价从低到高淘汰（见 evictLocked），**不**整表清空。
	evicted := 0
	if len(g.records) >= maxLoginRecords {
		evicted = g.evictLocked(now)
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
	g.mu.Unlock()

	if evicted > 0 {
		// 淘汰必须留痕：它意味着某些来源的计数被重置，排查「为什么没锁住」
		// 时这是唯一能看到的线索。
		log.Printf("[loginguard] 记录达到上限 %d，已按代价从低到高淘汰 %d 条", maxLoginRecords, evicted)
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
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
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
}

// evictLocked 在容量触顶时腾出空间。调用方必须持有 g.mu，返回淘汰条数。
//
// 不能整表清空。旧实现是「满了就 make 一张新表」，那等于给攻击者一个
// 重置所有锁定的开关：用海量随机账号/IP 把表灌满，正在被锁定的真实账号
// 会跟着一起解封——而这恰好发生在攻击进行中，是最不该放宽的时刻。
//
// 按代价从低到高逐级淘汰：
//
//  1. 已解锁且超过观察窗口的：本来就该消失，最没有代价；
//  2. 只失败过一次且已解锁的：丢掉最多让某个来源重新开始计数；
//  3. 仍然满：按最后失败时间淘汰仍未锁定的（最旧的先走）；
//  4. 极端情况（表里全是锁定中的）：只能按最后失败时间淘汰，
//     锁定状态提前失效——这是容量上限下无法避免的代价，但至少
//     只影响最旧的那批，而不是全体。
func (g *LoginGuard) evictLocked(now time.Time) int {
	removed := 0
	cutoff := now.Add(-2 * time.Hour)
	for k, rec := range g.records {
		if rec.lastFail.Before(cutoff) && now.After(rec.lockedTill) {
			delete(g.records, k)
			removed++
		}
	}
	if len(g.records) < maxLoginRecords {
		return removed
	}

	// 一次腾出 1/8：避免每来一个新键就全表扫一遍。
	target := maxLoginRecords - maxLoginRecords/8
	for k, rec := range g.records {
		if len(g.records) <= target {
			break
		}
		if rec.count <= 1 && now.After(rec.lockedTill) {
			delete(g.records, k)
			removed++
		}
	}
	if len(g.records) <= target {
		return removed
	}

	// 排序一次后按顺序删除：逐个找最旧是 O(n²)，而这里恰恰是满表状态。
	type candidate struct {
		key    string
		last   time.Time
		locked bool
	}
	cands := make([]candidate, 0, len(g.records))
	for k, rec := range g.records {
		cands = append(cands, candidate{
			key:    k,
			last:   rec.lastFail,
			locked: !now.After(rec.lockedTill),
		})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].locked != cands[j].locked {
			return !cands[i].locked // 未锁定的排在前面，优先淘汰
		}
		return cands[i].last.Before(cands[j].last)
	})
	for _, c := range cands {
		if len(g.records) <= target {
			break
		}
		delete(g.records, c.key)
		removed++
	}
	return removed
}
