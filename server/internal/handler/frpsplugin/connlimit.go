package frpsplugin

import (
	"log"
	"sync"
	"time"
)

const (
	connRatePerSec  = 300
	connBurst       = 800
	connCooldown    = time.Minute
	connSustainTrip = 20 * time.Second
	connOverGap     = 10 * time.Second
	connIdleTTL     = 10 * time.Minute
	connSweepEvery  = 1024
	connLogEvery    = 5 * time.Second
)

type connBucket struct {
	tokens       float64
	last         time.Time
	denied       int
	overSince    time.Time
	lastDeny     time.Time
	blockedUntil time.Time
	lastLog      time.Time
	lastSeen     time.Time
}

type connLimiter struct {
	mu      sync.Mutex
	buckets map[string]*connBucket
	now     func() time.Time
	calls   int
}

func newConnLimiter() *connLimiter {
	return &connLimiter{buckets: map[string]*connBucket{}, now: time.Now}
}

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

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * connRatePerSec
		if b.tokens > connBurst {
			b.tokens = connBurst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		b.endOverloadIfGap(now)
		return true, 0
	}

	if b.overSince.IsZero() || now.Sub(b.lastDeny) > connOverGap {
		b.overSince = now
		b.denied = 0
	}
	b.lastDeny = now
	b.denied++

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

func (b *connBucket) endOverloadIfGap(now time.Time) {
	if b.overSince.IsZero() {
		return
	}
	if now.Sub(b.lastDeny) > connOverGap {
		b.overSince = time.Time{}
		b.denied = 0
	}
}

func (l *connLimiter) logDenied(b *connBucket, now time.Time, key, reason string, wait time.Duration) {
	if !b.lastLog.IsZero() && now.Sub(b.lastLog) < connLogEvery {
		return
	}
	b.lastLog = now
	log.Printf("[plugin] 隧道 %s 新建连接被拒绝（%s），建议 %s 后重试",
		key, reason, wait.Round(time.Second))
}

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

func (l *connLimiter) maybeSweep(now time.Time) {
	l.calls++
	if l.calls%connSweepEvery != 0 {
		return
	}
	l.sweep(now)
}
