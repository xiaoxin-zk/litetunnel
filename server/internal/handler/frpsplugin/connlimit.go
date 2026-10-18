package frpsplugin

import (
	"log"
	"sync"
	"time"
)

// 每条隧道的新建连接速率限制与熔断参数。
//
// # 为什么需要
//
// 隧道端口直接暴露在公网。被扫描或压测时，frps 会为每一个 TCP 连接回调一次
// NewUserConn，面板与 frpc 都要跟着处理一次——流量不大，但连接数可以是无限的。
// 配额只约束「流量」，对「连接数」没有作用。
//
// # 为什么用令牌桶而不是硬阈值
//
// 正常业务也会有突发：游戏开局、页面刷新、客户端重连都会在瞬间产生几十个连接。
// 令牌桶允许这个突发，只把**持续**的高频连接挡在外面。
//
// 熔断是第二层：持续超限说明不是正常访问，冷却期内直接拒绝全部新连接，
// 让 frps 尽早关掉它们，避免一直陪着做握手与回调。
const (
	// connRatePerSec 是每条隧道每秒可持续接受的新连接数。
	//
	// 取值偏高是有意的：联机游戏的连接模式比网页激进得多——服务器列表刷新、
	// 大厅重连、每个玩家进入都要新建连接，热门房间一秒几百个并不罕见。
	// 限得太紧会把正常联机挡在门外，那比被刷更糟（用户找不到原因）。
	// 这里的阈值只拦「持续到不像人类操作」的量级。
	connRatePerSec = 300
	// connBurst 是允许的瞬时突发连接数。
	connBurst = 800
	// connCooldown 是熔断后的冷却时长。
	connCooldown = time.Minute
	// connSustainTrip 是「持续超限」触发熔断的时长。
	//
	// 只靠连续拒绝计数是不够的：流量长期略高于速率上限时，拒绝与成功会
	// 交替出现，计数器永远攒不满，熔断也就永远不触发。按持续时长判断，
	// 才能把「一直贴着上限摩擦」这类长期超限识别出来。
	connSustainTrip = 20 * time.Second
	// connOverGap 是判定「超限中断」的间隔：超过这么久没有新的拒绝，
	// 就认为上一轮超限已经结束，计数与起点重新开始。
	connOverGap = 10 * time.Second
	// connIdleTTL 是空闲隧道的计数记录保留时长。
	connIdleTTL = 10 * time.Minute
	// connSweepEvery 是每处理多少次回调清理一次空闲记录。
	connSweepEvery = 1024
	// connLogEvery 是同一隧道被拒日志的最小间隔。
	//
	// 被压测时拒绝是高频事件，逐条打日志等于用日志把磁盘打满——
	// 那正是攻击者想要的效果之一。
	connLogEvery = 5 * time.Second
)

// connBucket 是一条隧道的连接计数。
type connBucket struct {
	tokens float64
	last   time.Time
	// denied 是**本轮持续超限**内的拒绝次数，成功不会清零；
	// 只有超过 connOverGap 没有新的拒绝时才认为这一轮结束。
	denied int
	// overSince 是本轮持续超限的起点，零值表示当前没有超限。
	overSince    time.Time
	lastDeny     time.Time
	blockedUntil time.Time
	lastLog      time.Time
	lastSeen     time.Time
}

// connLimiter 按隧道维护令牌桶与熔断状态，全部在内存里，不落库。
//
// 进程重启后计数归零：这是有意的——限制针对的是「此刻正在发生的滥用」，
// 而不是要给某条隧道记一笔永久的账。
type connLimiter struct {
	mu      sync.Mutex
	buckets map[string]*connBucket
	// now 可被测试替换，用来推进时间而不真的 sleep。
	now   func() time.Time
	calls int
}

func newConnLimiter() *connLimiter {
	return &connLimiter{buckets: map[string]*connBucket{}, now: time.Now}
}

// allow 判断这次新建连接是否放行；不放行时返回建议的重试等待时长。
func (l *connLimiter) allow(key string) (bool, time.Duration) {
	if key == "" {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.maybeSweep(now)

	b := l.buckets[key]
	if b == nil {
		b = &connBucket{tokens: connBurst, last: now}
		l.buckets[key] = b
	}
	b.lastSeen = now

	if now.Before(b.blockedUntil) {
		l.logDenied(b, now, key, "熔断中", b.blockedUntil.Sub(now))
		return false, b.blockedUntil.Sub(now)
	}

	// 按经过的时间补令牌，上限为突发容量。
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * connRatePerSec
		if b.tokens > connBurst {
			b.tokens = connBurst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		// 成功**不清零** denied：略超限时拒绝与成功交替出现，清零会让
		// 熔断门槛永远达不到。只有超限真正中断了才重置。
		b.endOverloadIfGap(now)
		return true, 0
	}

	if b.overSince.IsZero() || now.Sub(b.lastDeny) > connOverGap {
		b.overSince = now
		b.denied = 0
	}
	b.lastDeny = now
	b.denied++

	// 两种触发方式：
	//   - 短时间内的密集拒绝（瞬时洪峰）；
	//   - 持续超限达到 connSustainTrip（长期略超限）。
	if b.denied >= connBurst || now.Sub(b.overSince) >= connSustainTrip {
		b.blockedUntil = now.Add(connCooldown)
		b.denied = 0
		b.overSince = time.Time{}
		b.tokens = 0
		log.Printf("[plugin] 隧道 %s 新建连接持续超出 %d/秒，熔断 %s",
			key, connRatePerSec, connCooldown)
		return false, connCooldown
	}
	l.logDenied(b, now, key, "超出速率", time.Second)
	return false, time.Second
}

// endOverloadIfGap 在超限已经中断时重置计数。
func (b *connBucket) endOverloadIfGap(now time.Time) {
	if b.overSince.IsZero() {
		return
	}
	if now.Sub(b.lastDeny) > connOverGap {
		b.overSince = time.Time{}
		b.denied = 0
	}
}

// logDenied 按间隔输出拒绝日志，避免日志本身成为攻击面。
func (l *connLimiter) logDenied(b *connBucket, now time.Time, key, reason string, wait time.Duration) {
	if !b.lastLog.IsZero() && now.Sub(b.lastLog) < connLogEvery {
		return
	}
	b.lastLog = now
	log.Printf("[plugin] 隧道 %s 新建连接被拒绝（%s），建议 %s 后重试",
		key, reason, wait.Round(time.Second))
}

// sweep 清理长时间没有连接的记录，并顺带做一次限频。
//
// 隧道名由用户控制，数量本身有上限（每条隧道一条记录）；这里清的是
// 「删掉隧道之后遗留的记录」，避免长期运行后 map 只增不减。
func (l *connLimiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if now.Before(b.blockedUntil) {
			continue
		}
		if now.Sub(b.lastSeen) > connIdleTTL {
			delete(l.buckets, k)
		}
	}
}

// maybeSweep 在每 connSweepEvery 次调用时清理一次。
func (l *connLimiter) maybeSweep(now time.Time) {
	l.calls++
	if l.calls%connSweepEvery != 0 {
		return
	}
	l.sweep(now)
}
