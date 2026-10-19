package service

import (
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (r *Runtime) AccessGuardReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.guardReady
}

func (r *Runtime) markAccessGuardReady() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guardReady = true
}

const guardRefreshInterval = 30 * time.Second

const guardMaxAge = 5 * time.Minute

func (s *Services) RefreshSessionGuard(runID string) {
	if runID == "" {
		return
	}
	sess, ok := s.Runtime.LookupSession(runID)
	if !ok {
		return
	}
	if !sess.GuardAt.IsZero() && time.Since(sess.GuardAt) < guardRefreshInterval {
		return
	}
	var u model.User
	err := s.DB.Preload("Group").First(&u, sess.UserID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		s.Runtime.SetSessionGuard(runID, true, true)
		return
	}
	if err != nil {
		return
	}
	if _, err := s.FindTrustedClientSession(runID); err != nil {
		s.Runtime.SetSessionGuard(runID, true, s.QuotaExceeded(&u))
		return
	}
	s.Runtime.SetSessionGuard(runID,
		u.Status != model.UserStatusActive,
		s.QuotaExceeded(&u))
}

const sessionAliveTTL = time.Second

func (s *Services) EnsureSessionOnline(runID string) bool {
	if runID == "" {
		return false
	}
	sess, ok := s.Runtime.LookupSession(runID)
	if !ok {
		return false
	}
	if !sess.AliveCheckedAt.IsZero() && time.Since(sess.AliveCheckedAt) < sessionAliveTTL {
		return !sess.Revoked
	}
	alive := true
	if _, err := s.FindTrustedClientSession(runID); err != nil {
		alive = false
	}
	s.Runtime.SetSessionAlive(runID, alive)
	return alive
}

func (s *Services) SessionGuard(runID string) (blocked, exceeded, ok bool) {
	if runID == "" {
		return false, false, false
	}
	sess, found := s.Runtime.LookupSession(runID)
	if !found || sess.GuardAt.IsZero() {
		return false, false, false
	}
	if time.Since(sess.GuardAt) > guardMaxAge {
		return true, sess.Exceeded, true
	}
	return sess.Blocked, sess.Exceeded, true
}

func (s *Services) PrimeSessionGuard(runID string, u *model.User) {
	if runID == "" || u == nil {
		return
	}
	if u.Group == nil && u.GroupID != 0 {
		var g model.Group
		if err := s.DB.First(&g, u.GroupID).Error; err == nil {
			u.Group = &g
		}
	}
	s.Runtime.SetSessionGuard(runID,
		u.Status != model.UserStatusActive,
		s.QuotaExceeded(u))
}

func (r *Runtime) IsQuotaExceeded(userID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.exceeded[userID]
}

func (r *Runtime) SetQuotaExceeded(userID uint, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
}

func (r *Runtime) SetQuotaExceededIfVer(userID uint, v bool, ver uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guardVer != ver {
		return false
	}
	if v {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
	return true
}

func (r *Runtime) BumpGuardVer() {
	r.mu.Lock()
	r.guardVer++
	r.mu.Unlock()
}

func (r *Runtime) GuardVer() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.guardVer
}

func (r *Runtime) SetGuardFlagsIfVer(userID uint, exceeded, blocked bool, ver uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guardVer != ver {
		return false
	}
	if exceeded {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
	if blocked {
		r.blocked[userID] = true
	} else {
		delete(r.blocked, userID)
	}
	return true
}

func (r *Runtime) IsUserBlocked(userID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.blocked[userID]
}

func (r *Runtime) SetUserBlocked(userID uint, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v {
		r.blocked[userID] = true
	} else {
		delete(r.blocked, userID)
	}
}

const quotaFullRefresh = 10 * time.Minute

func (s *Services) refreshGuardForTraffic(userDeltas map[uint]int64) {
	if len(userDeltas) == 0 {
		return
	}
	ids := make([]uint, 0, len(userDeltas))
	for id := range userDeltas {
		ids = append(ids, id)
	}
	if err := s.refreshQuotaFlagsFor(ids); err != nil {
		log.Printf("[quota] 刷新超额标记失败: %v", err)
	}
}

func (s *Services) refreshGuardDue() {
	periodDue, groupDue, err := s.dueGuardUsers()
	if err != nil {
		log.Printf("[quota] 查询到期用户失败: %v", err)
	}

	if len(groupDue) > 0 {
		if err := s.migrateExpiredGroups(groupDue); err != nil {
			log.Printf("[quota] 迁移到期分组用户失败（本轮仍按默认分组算标记）: %v", err)
		} else {
			s.Runtime.BumpGuardVer()
		}
	}

	if ids := append(periodDue, groupDue...); len(ids) > 0 {
		if err := s.refreshQuotaFlagsFor(ids); err != nil {
			log.Printf("[quota] 刷新到期用户标记失败: %v", err)
			s.guardFullAt.Store(0)
		}
	}

	if s.guardFullRefreshDue() {
		_ = s.refreshQuotaFlags()
	}
}

func (s *Services) migrateExpiredGroups(ids []uint) error {
	now := time.Now()
	for start := 0; start < len(ids); start += inQueryBatch {
		end := start + inQueryBatch
		if end > len(ids) {
			end = len(ids)
		}
		if err := s.DB.Transaction(func(tx *gorm.DB) error {
			batch := ids[start:end]
			var still []uint
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Model(&model.User{}).
				Where("id IN ? AND group_expire_at IS NOT NULL AND group_expire_at <= ?", batch, now).
				Pluck("id", &still).Error; err != nil {
				return err
			}
			if len(still) == 0 {
				return nil
			}
			g := s.defaultGroupTx(tx)
			if g == nil {
				return errors.New("没有默认分组，无法把到期用户落回默认分组")
			}
			if err := tx.Model(&model.User{}).
				Where("id IN ?", still).
				Updates(map[string]any{"group_id": g.ID, "group_expire_at": nil}).Error; err != nil {
				return err
			}
			return tx.Model(&model.Tunnel{}).Where("user_id IN ?", still).
				Update("bandwidth_limit", g.BandwidthLimit).Error
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Services) dueGuardUsers() (periodDue, groupDue []uint, err error) {
	now := time.Now()

	if err := s.DB.Model(&model.User{}).
		Where("traffic_reset_at <= ?", now).
		Pluck("id", &periodDue).Error; err != nil {
		return nil, nil, err
	}

	if err := s.DB.Model(&model.User{}).
		Where("group_expire_at IS NOT NULL AND group_expire_at <= ?", now).
		Pluck("id", &groupDue).Error; err != nil {
		return periodDue, nil, err
	}
	return periodDue, groupDue, nil
}

func (s *Services) guardFullRefreshDue() bool {
	now := time.Now().UnixNano()
	last := s.guardFullAt.Load()
	if last != 0 && now-last < int64(quotaFullRefresh) {
		return false
	}
	return s.guardFullAt.CompareAndSwap(last, now)
}

func (s *Services) refreshQuotaFlagsFor(userIDs []uint) error {
	const maxPasses = 3
	for pass := 0; ; pass++ {
		ver := s.Runtime.GuardVer()

		users := make([]model.User, 0, len(userIDs))
		for start := 0; start < len(userIDs); start += inQueryBatch {
			end := start + inQueryBatch
			if end > len(userIDs) {
				end = len(userIDs)
			}
			var batch []model.User
			if err := s.DB.Preload("Group").
				Where("id IN ?", userIDs[start:end]).Find(&batch).Error; err != nil {
				return err
			}
			users = append(users, batch...)
		}

		s.applyGuardFlags(users, ver)

		if s.Runtime.GuardVer() == ver {
			return nil
		}
		if pass+1 >= maxPasses {
			log.Printf("[quota] 配额标记刷新连续 %d 轮被管理操作打断，本轮放弃（下一轮重试）", maxPasses)
			return nil
		}
	}
}

func (s *Services) applyGuardFlags(users []model.User, ver uint64) {
	for i := range users {
		s.EnsureTrafficPeriod(&users[i])
		s.Runtime.SetGuardFlagsIfVer(users[i].ID,
			s.QuotaExceeded(&users[i]),
			users[i].Status != model.UserStatusActive,
			ver)
	}
}

func (s *Services) refreshQuotaFlags() error {
	const maxPasses = 3
	for pass := 0; ; pass++ {
		ver := s.Runtime.GuardVer()
		var users []model.User
		if err := s.DB.Preload("Group").Find(&users).Error; err != nil {
			log.Printf("[quota] 刷新超额标记失败: %v", err)
			return err
		}
		s.applyGuardFlags(users, ver)
		if s.Runtime.GuardVer() == ver {
			s.Runtime.markAccessGuardReady()
			s.guardFullAt.Store(time.Now().UnixNano())
			return nil
		}
		if pass+1 >= maxPasses {
			log.Printf("[quota] 配额标记刷新连续 %d 轮被管理操作打断，本轮不宣告就绪（下一轮采集重试）", maxPasses)
			return nil
		}
	}
}

func (s *Services) LoadAccessGuard() bool {
	if err := s.refreshQuotaFlags(); err != nil {
		log.Printf("[quota] 加载准入状态失败，在成功加载前将拒绝新建隧道: %v", err)
		return false
	}
	return s.Runtime.AccessGuardReady()
}
