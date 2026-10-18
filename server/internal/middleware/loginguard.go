package middleware

import (
	"log"
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
// 也正因如此，**多实例之间不共享**这份计数：轮换入口（不同实例）时
// 失败次数会被分散。这一点是硬锁的部署形态限制，不是这里能修好的：
// 键里带来源 IP，跨实例共享它需要一个共享存储 + 每个 IP 一条记录，
// 成本与收益不成比例。
//
// 它**不**意味着账号级防线也跟着失效：账号累计失败达阈值后要求验证码
// （见 service.CaptchaRequired）的计数已经落到数据库（lt_login_fail_counters），
// 多实例共用一个库时是共享的。这正是「硬锁按实例计、账号级验证码兜底」
// 这一组合成立的前提——否则多实例部署下账号级防线会随实例数摊薄。
type LoginGuard struct {
	// shards 把记录表切成若干片，每片独立加锁。
	//
	// 分片不是为了并发度，而是为了**把容量淘汰的代价压住**：表满时要
	// 按代价分级挑一批记录删掉，这一步必须在锁内完成。单表 10 万条时，
	// 一次淘汰最坏要扫 4 遍表，而它恰好发生在攻击进行中——每一次登录
	// 判定都可能排在这次扫描后面，表现为「被攻击时登录也变慢」。
	//
	// 16 片之后单片最多 6250 条，最坏持锁时间降到 1/16，且扫描量有上界。
	// key 是账号+IP，分布天然均匀；即便攻击者定向灌某一片，膨胀的也只是
	// 那一片，其余片照常判定。
	shards    [loginGuardShards]*guardShard
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

// loginGuardShards 是失败记录表的分片数。
//
// 必须是 2 的幂的约数不必要（取模即可），但保持与 maxLoginRecords 整除，
// 让「总容量」与单表时代保持一致，不会因为分片悄悄放宽限制。
const loginGuardShards = 16

// maxLoginRecords 是失败记录表的**总**容量上限。
//
// 没有上限时，攻击者用**随机用户名**持续制造失败记录，可以让这张表无限增长：
// GC 只清理 2 小时无活动的记录，而攻击者只要周期性再失败一次就能让它一直存活。
const maxLoginRecords = 100000

// guardShard 是分片后的记录表。
type guardShard struct {
	mu      sync.Mutex
	records map[string]*failureRecord
	// capacity 是本片容量，等于 maxLoginRecords / loginGuardShards。
	capacity int
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
		threshold: threshold,
		baseLock:  baseLock,
		maxLock:   maxLock,
		stop:      make(chan struct{}),
	}
	perShard := maxLoginRecords / loginGuardShards
	for i := range g.shards {
		g.shards[i] = &guardShard{
			records:  make(map[string]*failureRecord),
			capacity: perShard,
		}
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
	sh := g.shard(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()

	rec, ok := sh.records[key]
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
	sh := g.shard(key)

	sh.mu.Lock()
	// 容量保护：按代价从低到高淘汰（见 evictShardLocked），**不**整表清空。
	evicted := 0
	if len(sh.records) >= sh.capacity {
		evicted = evictShardLocked(sh, now)
	}

	rec, ok := sh.records[key]
	if !ok {
		rec = &failureRecord{}
		sh.records[key] = rec
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
	sh.mu.Unlock()

	if evicted > 0 {
		// 淘汰必须留痕：它意味着某些来源的计数被重置，排查「为什么没锁住」
		// 时这是唯一能看到的线索。
		log.Printf("[loginguard] 分片记录达到单片上限 %d，已按代价从低到高淘汰 %d 条", sh.capacity, evicted)
	}
}

// Reset 登录成功后清除失败记录。
func (g *LoginGuard) Reset(scope, account, ip string) {
	key := guardKey(scope, account, ip)
	sh := g.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	delete(sh.records, key)
}

// size 返回记录表的总条数。
//
// 只供测试与容量告警使用：登录判定本身从不需要总数（判定只看自己那一片）。
// 逐片加锁统计，不在任何一片上长时间持锁。
func (g *LoginGuard) size() int {
	n := 0
	for _, sh := range g.shards {
		sh.mu.Lock()
		n += len(sh.records)
		sh.mu.Unlock()
	}
	return n
}

// shard 按 key 定位分片。
func (g *LoginGuard) shard(key string) *guardShard {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime
	}
	return g.shards[h%loginGuardShards]
}

// gc 定期清理已解锁且长时间无活动的记录，避免内存无限增长。
//
// 逐片加锁而不是一次锁全表：清理是后台动作，没有理由让它在某一刻
// 挡住全部登录判定。片数固定，锁的获取顺序天然一致，不存在死锁。
func (g *LoginGuard) gc() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Hour)
			for _, sh := range g.shards {
				now := time.Now()
				sh.mu.Lock()
				for k, rec := range sh.records {
					if rec.lastFail.Before(cutoff) && now.After(rec.lockedTill) {
						delete(sh.records, k)
					}
				}
				sh.mu.Unlock()
			}
		}
	}
}

// evictShardLocked 在单片容量触顶时腾出空间。调用方必须持有该片的 mu，返回淘汰条数。
//
// 不能整表清空。旧实现是「满了就 make 一张新表」，那等于给攻击者一个
// 重置所有锁定的开关：用海量随机账号/IP 把表灌满，正在被锁定的真实账号
// 会跟着一起解封——而这恰好发生在攻击进行中，是最不该放宽的时刻。
//
// 按代价从低到高逐级淘汰，每一级都是**单遍扫描、不排序**：
//
//  1. 已解锁且超过观察窗口的：本来就该消失，最没有代价；
//  2. 只失败过一次且已解锁的：丢掉最多让某个来源重新开始计数；
//  3. 仍未满额：按遍历顺序淘汰未锁定的（map 遍历本身是伪随机，
//     攻击者无法定向保护某一条）；
//  4. 极端情况（表里全是锁定中的）：只能按遍历顺序淘汰。
//
// 为什么排序是错的：这条路径在互斥锁内，即使分片后单片也有数千条，
// 构建候选集再排序会把攻击期间的**每一次**登录判定都拖出长尾。
// 淘汰只需要「挑够数量」，不需要严格的最旧优先。
func evictShardLocked(sh *guardShard, now time.Time) int {
	removed := 0
	// 一次腾出 1/8：避免每来一个新键就扫一遍全片。
	target := sh.capacity - sh.capacity/8
	cutoff := now.Add(-2 * time.Hour)

	for k, rec := range sh.records {
		if len(sh.records) <= target {
			return removed
		}
		if rec.lastFail.Before(cutoff) && now.After(rec.lockedTill) {
			delete(sh.records, k)
			removed++
		}
	}
	if len(sh.records) < sh.capacity {
		return removed
	}

	for k, rec := range sh.records {
		if len(sh.records) <= target {
			break
		}
		if rec.count <= 1 && now.After(rec.lockedTill) {
			delete(sh.records, k)
			removed++
		}
	}
	if len(sh.records) <= target {
		return removed
	}

	for k, rec := range sh.records {
		if len(sh.records) <= target {
			break
		}
		if now.After(rec.lockedTill) {
			delete(sh.records, k)
			removed++
		}
	}

	// 表里可能全是锁定中的：只能牺牲一部分，优先让新流量继续可判定，
	// 而不是让所有判定都卡在满表上。
	for k := range sh.records {
		if len(sh.records) <= target {
			break
		}
		delete(sh.records, k)
		removed++
	}
	return removed
}
