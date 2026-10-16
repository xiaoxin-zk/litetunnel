package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 这一组测试守的是限流器的内存上界。
//
// 没有上界时，攻击者用大量分散来源的请求就能让 buckets 无限增长：
// GC 只清理 30 分钟无活动的桶，而攻击者只要持续换 IP 就能一直制造新桶。
// 与 LoginGuard 的 maxLoginRecords 是同一类问题，只是当初漏掉了限流器。

// TestRateLimiterEvictsOldestWhenFull 覆盖容量满时的淘汰策略。
func TestRateLimiterEvictsOldestWhenFull(t *testing.T) {
	rl := newRateLimiter(4, nil, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	if got := len(rl.buckets); got != 4 {
		t.Fatalf("桶数 = %d，期望 4", got)
	}

	// 第 5 个键：必须淘汰最久未用的 k1，且总数不超过上限。
	rl.Allow("k5")

	if got := len(rl.buckets); got != 4 {
		t.Fatalf("桶数 = %d，期望 4（不得超过上限）", got)
	}
	if _, ok := rl.buckets["k1"]; ok {
		t.Error("最久未用的 k1 应被淘汰")
	}
	if _, ok := rl.buckets["k5"]; !ok {
		t.Error("最新使用的 k5 必须保留")
	}
}

// TestRateLimiterKeepsRecentlyUsedKeys 覆盖 LRU 语义：
// 一个持续活跃的来源，不该被刚出现的陌生来源挤掉。
func TestRateLimiterKeepsRecentlyUsedKeys(t *testing.T) {
	rl := newRateLimiter(4, nil, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	// 让 k1 变成最近使用的：它此刻在最久未用的一端，必须被挪到另一端。
	rl.Allow("k1")
	rl.Allow("k5")

	if _, ok := rl.buckets["k2"]; ok {
		t.Error("k2 是最久未用的，应被淘汰")
	}
	if _, ok := rl.buckets["k1"]; !ok {
		t.Error("k1 刚被访问过，不该被淘汰")
	}
}

// TestRateLimiterBoundedUnderFlood 是容量上界的直接断言：
// 灌入远超上限的键，桶数必须始终不超过上限。
func TestRateLimiterBoundedUnderFlood(t *testing.T) {
	const cap = 32
	rl := newRateLimiter(cap, nil, 1, 10)

	for i := 0; i < cap*50; i++ {
		rl.Allow(fmt.Sprintf("ip-%d", i))
		if n := len(rl.buckets); n > cap {
			t.Fatalf("第 %d 个键之后桶数 = %d，超过上限 %d", i, n, cap)
		}
	}
	if got := len(rl.buckets); got != cap {
		t.Fatalf("最终桶数 = %d，期望 %d", got, cap)
	}
	if rl.evicted == 0 {
		t.Error("应当发生过淘汰")
	}
}

// TestRateLimiterStillLimits 确认淘汰机制没有把限流本身弄坏。
func TestRateLimiterStillLimits(t *testing.T) {
	// rate=0：不补充令牌，桶容量 1 —— 同一个键只放行一次。
	rl := newRateLimiter(2, nil, 0, 1)

	if !rl.Allow("a") {
		t.Fatal("第一次请求应放行")
	}
	if rl.Allow("a") {
		t.Fatal("第二次请求应被限流")
	}

	// 灌满容量，把 a 挤出去。
	rl.Allow("b")
	rl.Allow("c")
	if _, ok := rl.buckets["a"]; ok {
		t.Fatal("a 应已被淘汰")
	}

	// 被淘汰的来源会重新开始计数。这是容量受限下的既定取舍：
	// 与其整表清空（等于给所有人发满令牌，包括正在被限流的攻击者），
	// 不如只让最久未用的那部分重新开始。
	if !rl.Allow("a") {
		t.Error("被淘汰后的来源应重新获得一个满桶")
	}
}

// TestRateLimiterConcurrentAllow 覆盖并发下的正确性。
//
// 顺带断言一个不变量：LRU 链表长度必须始终等于桶数。
// 两者一旦不一致，说明有路径只删了 map 或只摘了链——那会让淘汰逻辑
// 去操作一个已经不存在的键，最终表现为「桶数没到上限却一直在淘汰」。
func TestRateLimiterConcurrentAllow(t *testing.T) {
	const cap = 64
	rl := newRateLimiter(cap, nil, 1, 10)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				rl.Allow(fmt.Sprintf("k-%d-%d", g, i))
			}
		}(g)
	}
	wg.Wait()

	if got := len(rl.buckets); got > cap {
		t.Fatalf("并发后桶数 = %d，超过上限 %d", got, cap)
	}
	if got, want := rl.lru.Len(), len(rl.buckets); got != want {
		t.Fatalf("LRU 节点数 %d 与桶数 %d 不一致", got, want)
	}
}

// TestRateLimiterWarnsThrottled 覆盖告警：淘汰必须被记录，
// 但同一时间窗内不能重复刷屏——洪水期间日志本身会变成放大器。
func TestRateLimiterWarnsThrottled(t *testing.T) {
	rl := newRateLimiter(1, nil, 1, 10)

	_, warn := rl.allow("k1")
	if warn != "" {
		t.Fatalf("尚未淘汰时不应告警: %q", warn)
	}

	// 第 2 个键把 k1 挤掉，触发第一次淘汰。
	_, warn = rl.allow("k2")
	if warn == "" {
		t.Fatal("首次淘汰必须告警")
	}

	// 紧接着再淘汰，应被限频。
	_, second := rl.allow("k3")
	if second != "" {
		t.Fatalf("同一时间窗内不应重复告警: %q", second)
	}
}

// TestRateLimiterDropIdleRemovesIdleBuckets 覆盖定期清理。
//
// 清理必须同时维护 LRU 链表：只从 map 里删、不摘链的话，链表会残留
// 已不存在的键，容量满时淘汰到的是一个空壳——表现为「桶数明明没到上限
// 却一直在淘汰」。
func TestRateLimiterDropIdleRemovesIdleBuckets(t *testing.T) {
	rl := newRateLimiter(4, nil, 1, 10)

	for _, k := range []string{"k1", "k2", "k3"} {
		rl.Allow(k)
	}

	// 把它们标记为久未活动，再走真实的清理路径。
	rl.mu.Lock()
	for _, b := range rl.buckets {
		b.lastSeen = b.lastSeen.Add(-time.Hour)
	}
	rl.mu.Unlock()

	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if got := len(rl.buckets); got != 0 {
		t.Fatalf("清理后仍有 %d 个桶", got)
	}
	if got := rl.lru.Len(); got != 0 {
		t.Fatalf("清理后 LRU 链表仍有 %d 个节点（应同步摘链）", got)
	}
}

// TestRateLimiterDropIdleKeepsActiveBuckets 确认清理不会误伤活跃来源。
func TestRateLimiterDropIdleKeepsActiveBuckets(t *testing.T) {
	rl := newRateLimiter(4, nil, 1, 10)
	rl.Allow("active")

	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if _, ok := rl.buckets["active"]; !ok {
		t.Fatal("刚访问过的桶不该被清理")
	}
}
