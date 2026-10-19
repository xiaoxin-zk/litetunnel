package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/controlplane"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type sessionInfo struct {
	UserID   uint
	Username string
	LastSeen time.Time

	GuardAt  time.Time
	Blocked  bool
	Exceeded bool

	AliveCheckedAt time.Time
	Revoked        bool
}

type Runtime struct {
	mu      sync.RWMutex
	control *controlplane.Client

	sessions map[string]sessionInfo
	exceeded map[uint]bool
	online   map[uint]bool
	lastStat map[string]trafficPair
	touchAt  map[string]time.Time

	baselineSeedPending bool

	resetMarkSeedPending bool

	pendingTrafficReset map[uint]uint64

	lastResetGen map[uint]int64

	resetSeq       uint64
	resetVoidUntil map[uint]uint64

	resetMu sync.Mutex

	guardVer uint64

	blocked map[uint]bool

	guardReady bool

	identities    map[identityKey]identityState
	identityGen   map[identityKey]uint64
	identityGenAt map[identityKey]time.Time

	identitySeq uint64
}

const (
	IdentityKindUser  uint8 = 1
	IdentityKindAdmin uint8 = 2
)

const identityTTL = 10 * time.Second

const identityGenGrace = 5 * time.Minute

const identityControlTimeout = 800 * time.Millisecond

type identityKey struct {
	kind uint8
	id   uint
}

type identityState struct {
	active  bool
	version int
	at      time.Time
}

func NewRuntime() *Runtime {
	return newRuntime(nil)
}

func newRuntime(control *controlplane.Client) *Runtime {
	return &Runtime{
		control:       control,
		sessions:      make(map[string]sessionInfo),
		exceeded:      make(map[uint]bool),
		blocked:       make(map[uint]bool),
		online:        make(map[uint]bool),
		lastStat:      make(map[string]trafficPair),
		touchAt:       make(map[string]time.Time),
		identities:    make(map[identityKey]identityState),
		identityGen:   make(map[identityKey]uint64),
		identityGenAt: make(map[identityKey]time.Time),
	}
}

func (r *Runtime) CachedIdentity(kind uint8, id uint) (bool, int, bool) {
	key := identityKey{kind: kind, id: id}
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.identities[key]
	if !ok || time.Since(st.at) > identityTTL {
		return false, 0, false
	}
	return st.active, st.version, true
}

func (r *Runtime) SetCachedIdentity(kind uint8, id uint, active bool, version int) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[key] = identityState{active: active, version: version, at: time.Now()}
}

func (r *Runtime) IdentityGen(kind uint8, id uint) uint64 {
	if r.control != nil && r.control.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), identityControlTimeout)
		defer cancel()
		if version, err := r.control.GetInt(ctx, fmt.Sprintf("identity:%d:%d", kind, id)); err == nil && version > 0 {
			r.ObserveIdentityVersion(kind, id, uint64(version))
		}
	}
	key := identityKey{kind: kind, id: id}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identityGen[key]
}

func (r *Runtime) ObserveIdentityVersion(kind uint8, id uint, version uint64) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if version > r.identityGen[key] {
		r.identityGen[key] = version
		r.identityGenAt[key] = time.Now()
		delete(r.identities, key)
	}
}

func (r *Runtime) SetCachedIdentityIfGen(kind uint8, id uint, active bool, version int, gen uint64) bool {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.identityGen[key] != gen {
		return false
	}
	r.identities[key] = identityState{active: active, version: version, at: time.Now()}
	return true
}

func (r *Runtime) InvalidateIdentity(kind uint8, id uint) {
	key := identityKey{kind: kind, id: id}
	if r.control != nil && r.control.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), identityControlTimeout)
		err := func() error {
			defer cancel()
			_, err := r.control.BumpVersion(ctx, fmt.Sprintf("identity:%d:%d", kind, id))
			return err
		}()
		if err != nil {
			log.Printf("[runtime] 共享身份失效版本更新失败（kind=%d id=%d）: %v", kind, id, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.identityGen == nil {
		r.identityGen = map[identityKey]uint64{}
	}
	if r.identityGenAt == nil {
		r.identityGenAt = map[identityKey]time.Time{}
	}
	r.identitySeq++
	r.identityGen[key] = r.identitySeq
	r.identityGenAt[key] = time.Now()
	delete(r.identities, key)
}

func (r *Runtime) ShouldTouch(runID string, interval time.Duration) bool {
	if runID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.touchAt[runID]
	if ok && time.Since(last) < interval {
		return false
	}
	r.touchAt[runID] = time.Now()
	return true
}

func (s *Services) TouchClientSession(runID string) {
	if !s.Runtime.ShouldTouch(runID, time.Minute) {
		return
	}
	res := s.DB.Model(&model.ClientSession{}).
		Where("run_id = ? AND online = ?", runID, true).
		Update("last_seen_at", time.Now())
	if res.Error != nil {
		log.Printf("[session] 刷新会话心跳失败（run_id=%s）: %v", runID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		log.Printf("[session] 心跳未命中在线会话（run_id=%s，可能已被撤销），已忽略", runID)
	}
}

const sessionTrustWindow = 10 * time.Minute

func (s *Services) FindTrustedClientSession(runID string) (*model.ClientSession, error) {
	if runID == "" {
		return nil, ErrNotFound
	}
	var sess model.ClientSession
	err := s.DB.Where("run_id = ? AND online = ?", runID, true).First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Since(sess.LastSeenAt) > sessionTrustWindow {
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (s *Services) MarkStaleSessionsOffline(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	if err := s.DB.Model(&model.ClientSession{}).
		Where("online = ? AND last_seen_at < ?", true, cutoff).
		Update("online", false).Error; err != nil {
		log.Printf("[session] 标记陈旧会话离线失败（在线列表可能残留幽灵会话）: %v", err)
		s.recordAuditFailure(auditScopeSessionSweep, err)
	}
}

func (r *Runtime) RecordLogin(runID string, userID uint, username string) {
	if runID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[runID] = sessionInfo{UserID: userID, Username: username, LastSeen: time.Now()}
}

func (r *Runtime) LookupSession(runID string) (sessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[runID]
	return s, ok
}

func (r *Runtime) TouchSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.LastSeen = time.Now()
		r.sessions[runID] = s
	}
}

func (r *Runtime) SetSessionGuard(runID string, blocked, exceeded bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.Blocked = blocked
		s.Exceeded = exceeded
		s.GuardAt = time.Now()
		r.sessions[runID] = s
	}
}

func (r *Runtime) SetSessionAlive(runID string, alive bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.AliveCheckedAt = time.Now()
		s.Revoked = !alive
		r.sessions[runID] = s
	}
}

func (r *Runtime) DropSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, runID)
	delete(r.touchAt, runID)
}

func (r *Runtime) DropUserSessions(userID uint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for runID, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, runID)
			delete(r.touchAt, runID)
			n++
		}
	}
	return n
}

func (s *Services) tunnelOnlineGrace() time.Duration {
	grace := 2 * s.Cfg.TrafficPollInterval
	if grace < time.Minute {
		grace = time.Minute
	}
	return grace
}

func (s *Services) IsTunnelOnline(t *model.Tunnel) bool {
	if t == nil || t.LastOnlineAt == nil {
		return false
	}
	return time.Since(*t.LastOnlineAt) <= s.tunnelOnlineGrace()
}

func (r *Runtime) IsTunnelOnline(tunnelID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.online[tunnelID]
}

func (r *Runtime) setOnlineTunnels(m map[uint]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.online = m
}

func (r *Runtime) GC(maxIdle time.Duration) {
	now := time.Now()
	cutoff := now.Add(-maxIdle)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.sessions {
		if v.LastSeen.Before(cutoff) {
			delete(r.sessions, k)
			delete(r.touchAt, k)
		}
	}
	for k, at := range r.touchAt {
		if at.Before(cutoff) {
			delete(r.touchAt, k)
		}
	}

	r.gcIdentitiesLocked(now)
}

func (r *Runtime) gcIdentitiesLocked(now time.Time) {
	for k, st := range r.identities {
		if now.Sub(st.at) > identityTTL {
			delete(r.identities, k)
		}
	}
	for k, at := range r.identityGenAt {
		if _, cached := r.identities[k]; cached {
			continue
		}
		if now.Sub(at) > identityGenGrace {
			delete(r.identityGen, k)
			delete(r.identityGenAt, k)
		}
	}
}
