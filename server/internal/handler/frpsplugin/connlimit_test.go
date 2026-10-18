package frpsplugin

import (
	"testing"
	"time"
)

func fixedClock(start time.Time) (*connLimiter, *time.Time) {
	l := newConnLimiter()
	now := start
	l.now = func() time.Time { return now }
	return l, &now
}

// TestConnLimiterAllowsBurstThenRateLimits 覆盖「突发放行、持续超限拒绝」。
func TestConnLimiterAllowsBurstThenRateLimits(t *testing.T) {
	l, now := fixedClock(time.Unix(1000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		if ok, _ := l.allow(key); !ok {
			t.Fatalf("突发内的第 %d 个连接应放行", i+1)
		}
	}
	if ok, wait := l.allow(key); ok || wait <= 0 {
		t.Fatalf("突发耗尽后应拒绝并给出等待时长，实际 ok=%v wait=%v", ok, wait)
	}

	// 过一秒，按每秒速率补充令牌。
	*now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < connRatePerSec; i++ {
		if ok, _ := l.allow(key); ok {
			allowed++
		}
	}
	if allowed != connRatePerSec {
		t.Fatalf("一秒后应恰好恢复 %d 个连接，实际 %d", connRatePerSec, allowed)
	}
}

// TestConnLimiterTripsAndRecovers 覆盖熔断与恢复。
func TestConnLimiterTripsAndRecovers(t *testing.T) {
	l, now := fixedClock(time.Unix(2000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	// 继续打到连续拒绝阈值，应触发冷却。
	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	if ok, wait := l.allow(key); ok || wait > connCooldown {
		t.Fatalf("熔断后应拒绝且等待不超过冷却时长，实际 ok=%v wait=%v", ok, wait)
	}

	// 冷却期内即使时间只走了一半也仍然拒绝。
	*now = now.Add(connCooldown / 2)
	if ok, _ := l.allow(key); ok {
		t.Fatal("冷却期内不该放行")
	}

	*now = now.Add(connCooldown)
	if ok, _ := l.allow(key); !ok {
		t.Fatal("冷却结束后应恢复放行")
	}
}

// TestConnLimiterTripsOnSustainedSlightOverload 覆盖「略超限时熔断永远不触发」。
//
// 流量长期略高于速率上限时，拒绝与成功会交替出现。若每次成功都把拒绝计数
// 清零，计数器永远攒不满，熔断形同不存在——限流还在，但长期滥用不会被切断。
func TestConnLimiterTripsOnSustainedSlightOverload(t *testing.T) {
	l, now := fixedClock(time.Unix(5000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}

	// 之后每秒 310 个请求：约 300 个放行、10 个被拒。
	tripped := false
	for sec := 0; sec < 30 && !tripped; sec++ {
		*now = now.Add(time.Second)
		for i := 0; i < connRatePerSec+10; i++ {
			if ok, wait := l.allow(key); !ok && wait >= connCooldown {
				tripped = true
			}
		}
	}
	if !tripped {
		t.Fatal("持续略超限应在达到持续时长后触发熔断")
	}
}

// TestConnLimiterResetsAfterOverloadGap 覆盖反面：超限中断后重新计数，
// 零星的拒绝不能累计成熔断。
func TestConnLimiterResetsAfterOverloadGap(t *testing.T) {
	l, now := fixedClock(time.Unix(6000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	for i := 0; i < 50; i++ {
		l.allow(key)
	}

	// 间隔超过判定阈值后再放行一次：这一轮超限应当被认定结束。
	*now = now.Add(connOverGap + time.Second)
	if ok, _ := l.allow(key); !ok {
		t.Fatal("间隔足够久之后应恢复放行")
	}

	l.mu.Lock()
	b := l.buckets[key]
	reset := b.denied == 0 && b.overSince.IsZero()
	l.mu.Unlock()
	if !reset {
		t.Fatalf("超限中断后计数应归零，实际 denied=%d overSince=%v", b.denied, b.overSince)
	}
}

// TestConnLimiterIsolatesTunnels 覆盖按隧道独立计数。
func TestConnLimiterIsolatesTunnels(t *testing.T) {
	l, _ := fixedClock(time.Unix(3000, 0))
	for i := 0; i < connBurst; i++ {
		l.allow("run|mc")
	}
	if ok, _ := l.allow("run|mc"); ok {
		t.Fatal("被压的隧道应拒绝")
	}
	if ok, _ := l.allow("run|other"); !ok {
		t.Fatal("另一条隧道不该受影响")
	}
}

// TestConnLimiterSweepsIdleBuckets 覆盖空闲记录清理，避免长期运行后只增不减。
func TestConnLimiterSweepsIdleBuckets(t *testing.T) {
	l, now := fixedClock(time.Unix(4000, 0))
	l.allow("run|mc")
	if len(l.buckets) != 1 {
		t.Fatalf("应记录一条计数，实际 %d", len(l.buckets))
	}
	l.sweep(now.Add(connIdleTTL + time.Minute))
	if len(l.buckets) != 0 {
		t.Fatalf("空闲超过 TTL 的记录应被清理，实际 %d", len(l.buckets))
	}
}
