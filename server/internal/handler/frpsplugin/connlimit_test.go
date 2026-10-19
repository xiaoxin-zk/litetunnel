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

func TestConnLimiterTripsAndRecovers(t *testing.T) {
	l, now := fixedClock(time.Unix(2000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	if ok, wait := l.allow(key); ok || wait > connCooldown {
		t.Fatalf("熔断后应拒绝且等待不超过冷却时长，实际 ok=%v wait=%v", ok, wait)
	}

	*now = now.Add(connCooldown / 2)
	if ok, _ := l.allow(key); ok {
		t.Fatal("冷却期内不该放行")
	}

	*now = now.Add(connCooldown)
	if ok, _ := l.allow(key); !ok {
		t.Fatal("冷却结束后应恢复放行")
	}
}

func TestConnLimiterTripsOnSustainedSlightOverload(t *testing.T) {
	l, now := fixedClock(time.Unix(5000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}

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

func TestConnLimiterResetsAfterOverloadGap(t *testing.T) {
	l, now := fixedClock(time.Unix(6000, 0))
	const key = "run|mc"

	for i := 0; i < connBurst; i++ {
		l.allow(key)
	}
	for i := 0; i < 50; i++ {
		l.allow(key)
	}

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
