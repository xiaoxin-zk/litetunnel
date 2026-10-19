package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newSingleShardLimiter(maxSize int, rate, capacity float64) *RateLimiter {
	return newShardedRateLimiter(1, maxSize, nil, rate, capacity)
}

func (rl *RateLimiter) bucketCount() int {
	n := 0
	for _, sh := range rl.shards {
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

func (rl *RateLimiter) lruLen() int {
	n := 0
	for _, sh := range rl.shards {
		sh.mu.Lock()
		n += sh.lru.Len()
		sh.mu.Unlock()
	}
	return n
}

func (rl *RateLimiter) hasBucket(key string) bool {
	sh := rl.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	_, ok := sh.buckets[key]
	return ok
}

func (rl *RateLimiter) ageAllBuckets(d time.Duration) {
	for _, sh := range rl.shards {
		sh.mu.Lock()
		for _, b := range sh.buckets {
			b.lastSeen = b.lastSeen.Add(d)
		}
		sh.mu.Unlock()
	}
}

func (rl *RateLimiter) shardCapacities() []int {
	out := make([]int, len(rl.shards))
	for i, sh := range rl.shards {
		out[i] = sh.maxSize
	}
	return out
}

func TestRateLimiterEvictsOldestWhenFull(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	if got := rl.bucketCount(); got != 4 {
		t.Fatalf("桶数 = %d，期望 4", got)
	}

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

func TestRateLimiterKeepsRecentlyUsedKeys(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		rl.Allow(k)
	}
	rl.Allow("k1")
	rl.Allow("k5")

	if rl.hasBucket("k2") {
		t.Error("k2 是最久未用的，应被淘汰")
	}
	if !rl.hasBucket("k1") {
		t.Error("k1 刚被访问过，不该被淘汰")
	}
}

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

func TestRateLimiterStillLimits(t *testing.T) {
	rl := newSingleShardLimiter(2, 0, 1)

	if !rl.Allow("a") {
		t.Fatal("第一次请求应放行")
	}
	if rl.Allow("a") {
		t.Fatal("第二次请求应被限流")
	}

	rl.Allow("b")
	rl.Allow("c")
	if rl.hasBucket("a") {
		t.Fatal("a 应已被淘汰")
	}

	if !rl.Allow("a") {
		t.Error("被淘汰后的来源应重新获得一个满桶")
	}
}

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

func TestRateLimiterWarnsThrottled(t *testing.T) {
	rl := newSingleShardLimiter(1, 1, 10)

	_, warn := rl.allow("k1")
	if warn != "" {
		t.Fatalf("尚未淘汰时不应告警: %q", warn)
	}

	_, warn = rl.allow("k2")
	if warn == "" {
		t.Fatal("首次淘汰必须告警")
	}

	_, second := rl.allow("k3")
	if second != "" {
		t.Fatalf("同一时间窗内不应重复告警: %q", second)
	}
}

func TestRateLimiterDropIdleRemovesIdleBuckets(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)

	for _, k := range []string{"k1", "k2", "k3"} {
		rl.Allow(k)
	}

	rl.ageAllBuckets(-time.Hour)
	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if got := rl.bucketCount(); got != 0 {
		t.Fatalf("清理后仍有 %d 个桶", got)
	}
	if got := rl.lruLen(); got != 0 {
		t.Fatalf("清理后 LRU 链表仍有 %d 个节点（应同步摘链）", got)
	}
}

func TestRateLimiterDropIdleKeepsActiveBuckets(t *testing.T) {
	rl := newSingleShardLimiter(4, 1, 10)
	rl.Allow("active")

	rl.dropIdle(time.Now().Add(-30 * time.Minute))

	if !rl.hasBucket("active") {
		t.Fatal("刚访问过的桶不该被清理")
	}
}

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

func TestRateLimiterShardsIsolateEviction(t *testing.T) {
	rl := newShardedRateLimiter(4, 8, nil, 0, 1)

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
