package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 这一组测试守的是限流器的内存上界与令牌桶语义。
//
// 没有上界时，攻击者用大量分散来源的请求就能让桶表无限增长：
// GC 只清理 30 分钟无活动的桶，而攻击者只要持续换 IP 就能一直制造新桶。
// 与 LoginGuard 的 maxLoginRecords 是同一类问题，只是当初漏掉了限流器。
//
// 限流器后来拆成了分片（见 middleware.go 的 limiterShardCount）。分片把
// 「全局 LRU」变成了「分片内 LRU」，因此下面有两类用例：
//   - 令牌桶与淘汰策略本身：用单分片构造，让「谁最久未用」是全局可判定的，
//     这样断言才确定；
//   - 分片行为：用多分片构造，断言总容量不变、各片容量之和等于上限、
//     以及分片之间互不影响。

// newSingleShardLimiter 构造单分片限流器，用于验证令牌桶与 LRU 策略本身。
//
// 单分片时「分片内最久未用」就是「全局最久未用」，淘汰顺序可精确断言。
func newSingleShardLimiter(maxSize int, rate, capacity float64) *RateLimiter {
	return newShardedRateLimiter(1, maxSize, nil, rate, capacity)
}

// bucketCount 返回所有分片的桶总数。
func (rl *RateLimiter) bucketCount() int {
	n := 0
	for _, sh := range rl.shards {
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

// lruLen 返回所有分片 LRU 链表的节点总数。
func (rl *RateLimiter) lruLen() int {
	n := 0
	for _, sh := range rl.shards {
		sh.mu.Lock()
		n += sh.lru.Len()
		sh.mu.Unlock()
	}
	return n
}

// hasBucket 判断某个键当前是否还有令牌桶（会按哈希定位到它的分片）。
func (rl *RateLimiter) hasBucket(key string) bool {
	sh := rl.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	_, ok := sh.buckets[key]
	return ok
}

// ageAllBuckets 把所有桶的最后活动时间往前推 d，用于模拟「久未活动」。
//
// 直接改内部状态而不是 sleep：清理逻辑测的是时间比较，不是等待本身，
// 真等 30 分钟会让测试不可接受。
func (rl *RateLimiter) ageAllBuckets(d time.Duration) {
	for _, sh := range rl.shards {
		sh.mu.Lock()
		for _, b := range sh.buckets {
			b.lastSeen = b.lastSeen.Add(d)
		}
		sh.mu.Unlock()
	}
}

// shardCapacities 返回各分片的容量上限。
func (rl *RateLimiter) shardCapacities() []int {
	out := make([]int, len(rl.shards))
	for i, sh := range rl.shards {
		out[i] = sh.maxSize
	}
	return out
}

// TestRateLimiterEvictsOldestWhenFull 覆盖容量满时的淘汰策略。
func TestRateLimiterEvictsOldestWhenFull(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	if got := rl.bucketCount(); got != 4 {
		t.Fatalf("桶数 = %d，期望 4", got)
	}

	// 第 5 个键：必须淘汰最久未用的 k1，且总数不超过上限。
	rl.Allow("k5")

	if got := rl.bucketCount(); got != 4 {
		t.Fatalf("桶数 = %d，期望 4（不得超过上限）", got)
	}
	if rl.hasBucket("k1") {
		t.Error("最久未用的 k1 应被淘汰")
	}
	if !rl.hasBucket("k5") {
		t.Error("最新使用的 k5 必须保留")
	}
}

// TestRateLimiterKeepsRecentlyUsedKeys 覆盖 LRU 语义：
// 一个持续活跃的来源，不该被刚出现的陌生来源挤掉。
func TestRateLimiterKeepsRecentlyUsedKeys(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	// 让 k1 变成最近使用的：它此刻在最久未用的一端，必须被挪到另一端。
	rl.Allow("k1")
	rl.Allow("k5")

	if rl.hasBucket("k2") {
		t.Error("k2 是最久未用的，应被淘汰")
	}
	if !rl.hasBucket("k1") {
		t.Error("k1 刚被访问过，不该被淘汰")
	}
}

// TestRateLimiterBoundedUnderFlood 是容量上界的直接断言：
// 灌入远超上限的键，桶数必须始终不超过上限。
func TestRateLimiterBoundedUnderFlood(t *testing.T) {
	const capacity = 32
	rl := newSingleShardLimiter(capacity, 1, 10)

	for i := 0; i < capacity*50; i++ {
		rl.Allow(fmt.Sprintf("ip-%d", i))
		if n := rl.bucketCount(); n > capacity {
			t.Fatalf("第 %d 个键之后桶数 = %d，超过上限 %d", i, n, capacity)
		}
	}
	if got := rl.bucketCount(); got != capacity {
		t.Fatalf("最终桶数 = %d，期望 %d", got, capacity)
	}
	if rl.evicted.Load() == 0 {
		t.Error("应当发生过淘汰")
	}
}

// TestRateLimiterStillLimits 确认淘汰机制没有把限流本身弄坏。
func TestRateLimiterStillLimits(t *testing.T) {
	// rate=0：不补充令牌，桶容量 1 —— 同一个键只放行一次。
	rl := newSingleShardLimiter(2, 0, 1)

	if !rl.Allow("a") {
		t.Fatal("第一次请求应放行")
	}
	if rl.Allow("a") {
		t.Fatal("第二次请求应被限流")
	}

	// 灌满容量，把 a 挤出去。
	rl.Allow("b")
	rl.Allow("c")
	if rl.hasBucket("a") {
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
	const capacity = 64
	rl := newSingleShardLimiter(capacity, 1, 10)

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

	if got := rl.bucketCount(); got > capacity {
		t.Fatalf("并发后桶数 = %d，超过上限 %d", got, capacity)
	}
	if got, want := rl.lruLen(), rl.bucketCount(); got != want {
		t.Fatalf("LRU 节点数 %d 与桶数 %d 不一致", got, want)
	}
}

// TestRateLimiterWarnsThrottled 覆盖告警：淘汰必须被记录，
// 但同一时间窗内不能重复刷屏——洪水期间日志本身会变成放大器。
func TestRateLimiterWarnsThrottled(t *testing.T) {
	rl := newSingleShardLimiter(1, 1, 10)

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
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3"} {
		rl.Allow(k)
	}

	// 把它们标记为久未活动，再走真实的清理路径。
	rl.ageAllBuckets(-time.Hour)
	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if got := rl.bucketCount(); got != 0 {
		t.Fatalf("清理后仍有 %d 个桶", got)
	}
	if got := rl.lruLen(); got != 0 {
		t.Fatalf("清理后 LRU 链表仍有 %d 个节点（应同步摘链）", got)
	}
}

// TestRateLimiterDropIdleKeepsActiveBuckets 确认清理不会误伤活跃来源。
func TestRateLimiterDropIdleKeepsActiveBuckets(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)
	rl.Allow("active")

	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if !rl.hasBucket("active") {
		t.Fatal("刚访问过的桶不该被清理")
	}
}

// TestRateLimiterShardCapacitySumsToMax 守「分片不放大内存上限」：
// 各分片容量之和必须恰好等于配置的上限，且每片至少 1。
func TestRateLimiterShardCapacitySumsToMax(t *testing.T) {
	for _, maxSize := range []int{1, 2, 3, 4, 15, 16, 17, 100, maxBuckets} {
		rl := newShardedRateLimiter(limiterShardCount, maxSize, nil, 1, 10)
		sum := 0
		for _, c := range rl.shardCapacities() {
			if c < 1 {
				t.Fatalf("maxSize=%d 时出现容量为 %d 的分片：该片上的限流会失效", maxSize, c)
			}
			sum += c
		}
		if sum != maxSize {
			t.Fatalf("maxSize=%d：分片容量之和 = %d，必须恰好等于上限", maxSize, sum)
		}
		if len(rl.shards)&(len(rl.shards)-1) != 0 {
			t.Fatalf("maxSize=%d：分片数 %d 不是 2 的幂，无法用位与定位分片", maxSize, len(rl.shards))
		}
	}
}

// TestRateLimiterShardsBoundTotalBuckets 守「分片后总量仍然有界」：
// 洪水灌入远超上限的分散键，总桶数不得超过上限，且各片都不超自己的配额。
func TestRateLimiterShardsBoundTotalBuckets(t *testing.T) {
	const capacity = 256
	rl := newShardedRateLimiter(8, capacity, nil, 1, 10)

	for i := 0; i < capacity*20; i++ {
		rl.Allow(fmt.Sprintf("ip-%d", i))
		if n := rl.bucketCount(); n > capacity {
			t.Fatalf("第 %d 个键之后总桶数 = %d，超过上限 %d", i, n, capacity)
		}
	}

	if got := rl.bucketCount(); got != capacity {
		t.Fatalf("最终总桶数 = %d，期望 %d（应填满但不超过）", got, capacity)
	}
	if rl.evicted.Load() == 0 {
		t.Error("应当发生过淘汰")
	}
	// 每片都不能超过自己的配额：分片只是把容量切开，不能各自放大。
	caps := rl.shardCapacities()
	for i, sh := range rl.shards {
		sh.mu.Lock()
		n := len(sh.buckets)
		sh.mu.Unlock()
		if n > caps[i] {
			t.Fatalf("第 %d 片桶数 = %d，超过该片配额 %d", i, n, caps[i])
		}
	}
	if got, want := rl.lruLen(), rl.bucketCount(); got != want {
		t.Fatalf("LRU 节点数 %d 与桶数 %d 不一致", got, want)
	}
}

// TestRateLimiterShardsIsolateEviction 守「分片之间互不影响」：
// 一个分片被灌满并淘汰，不该动到另一个分片里的活跃桶。
//
// 这正是分片的目的：热点键的淘汰压力被限制在它自己的分片内。
func TestRateLimiterShardsIsolateEviction(t *testing.T) {
	rl := newShardedRateLimiter(4, 8, nil, 0, 1)

	// 每个分片的容量由构造器均分（8 / 4 = 2）。按实际配额构造，
	// 否则「灌满」这一步的键数就是猜的，用例会在配额变化时静默失效。
	const shardIdx = 0
	shardCap := rl.shardCapacities()[shardIdx]
	if shardCap < 1 {
		t.Fatalf("分片容量为 %d，无法构造", shardCap)
	}
	var sameShard []string
	for i := 0; len(sameShard) < shardCap && i < 100000; i++ {
		k := fmt.Sprintf("hot-%d", i)
		if rl.shardFor(k) == rl.shards[shardIdx] {
			sameShard = append(sameShard, k)
		}
	}
	if len(sameShard) != shardCap {
		t.Fatalf("找不到足够的同分片键（需要 %d 个，找到 %d 个）", shardCap, len(sameShard))
	}

	// 另一个分片里的键：必须在灌爆 shard 0 之后仍然存在。
	var otherKey string
	for i := 0; otherKey == "" && i < 10000; i++ {
		k := fmt.Sprintf("cold-%d", i)
		if rl.shardFor(k) != rl.shards[shardIdx] {
			otherKey = k
		}
	}
	if otherKey == "" {
		t.Fatal("找不到落在其它分片上的键")
	}
	if !rl.Allow(otherKey) {
		t.Fatal("冷分片首次请求应放行")
	}

	for _, k := range sameShard {
		rl.Allow(k)
	}
	// 再插入一个同分片键，触发 shard 0 内淘汰。
	for i := 0; i < 10000; i++ {
		k := fmt.Sprintf("hot-extra-%d", i)
		if rl.shardFor(k) == rl.shards[shardIdx] {
			rl.Allow(k)
			break
		}
	}

	if !rl.hasBucket(otherKey) {
		t.Error("另一个分片里的桶被误淘汰：分片之间不该互相影响")
	}
}
