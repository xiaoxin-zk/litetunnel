package middleware

import (
	"log"
	"strings"
	"sync"
	"time"
)

type LoginGuard struct {
	shards    [loginGuardShards]*guardShard
	threshold int
	baseLock  time.Duration
	maxLock   time.Duration

	stop      chan struct{}
	closeOnce sync.Once
}

const loginGuardShards = 16

const maxLoginRecords = 100000

type guardShard struct {
	mu       sync.Mutex
	records  map[string]*failureRecord
	capacity int
}

type failureRecord struct {
	count      int
	lockedTill time.Time
	lastFail   time.Time
}

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

func (g *LoginGuard) Close() {
	if g == nil {
		return
	}
	g.closeOnce.Do(func() { close(g.stop) })
}

func guardKey(scope, account, ip string) string {
	return scope + "|" + strings.ToLower(strings.TrimSpace(account)) + "|" + ip
}

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

func (g *LoginGuard) Fail(scope, account, ip string) {
	key := guardKey(scope, account, ip)
	now := time.Now()
	sh := g.shard(key)

	sh.mu.Lock()
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
		over := rec.count - g.threshold
		if over > 20 {
			over = 20
		}
		lock := g.baseLock << uint(over)
		if lock <= 0 || lock > g.maxLock {
			lock = g.maxLock
		}
		rec.lockedTill = now.Add(lock)
	}
	sh.mu.Unlock()

	if evicted > 0 {
		log.Printf("[loginguard] 分片记录达到单片上限 %d，已按代价从低到高淘汰 %d 条", sh.capacity, evicted)
	}
}

func (g *LoginGuard) Reset(scope, account, ip string) {
	key := guardKey(scope, account, ip)
	sh := g.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	delete(sh.records, key)
}

func (g *LoginGuard) size() int {
	n := 0
	for _, sh := range g.shards {
		sh.mu.Lock()
		n += len(sh.records)
		sh.mu.Unlock()
	}
	return n
}

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

func evictShardLocked(sh *guardShard, now time.Time) int {
	removed := 0
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

	for k := range sh.records {
		if len(sh.records) <= target {
			break
		}
		delete(sh.records, k)
		removed++
	}
	return removed
}
