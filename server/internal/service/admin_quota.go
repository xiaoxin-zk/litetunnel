package service

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) AdminSetUserQuota(id uint, quota int64) error {
	if quota < 0 {
		return fmt.Errorf("%w: 配额不能为负数", ErrInvalidParam)
	}
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	res := s.DB.Model(&model.User{}).Where("id = ?", id).Update("traffic_quota", quota)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

func (s *Services) AdminResetUserTraffic(id uint) error {
	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

	gen := s.Runtime.MarkTrafficResetPending(id)
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"traffic_used":      0,
		"traffic_reset_gen": gorm.Expr("traffic_reset_gen + 1"),
		"traffic_reset_at":  time.Now().AddDate(0, 1, 0),
	})
	if res.Error != nil {
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return res.Error
	}
	if res.RowsAffected == 0 {
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return ErrNotFound
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(id, false)
	return nil
}

func (s *Services) refreshQuotaFor(id uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		u, err := s.LoadUser(id)
		if err != nil {
			return fmt.Errorf("刷新配额标记失败（用户 %d）: %w", id, err)
		}
		exceeded := s.QuotaExceeded(u)
		if s.Runtime.SetQuotaExceededIfVer(u.ID, exceeded, ver) {
			return nil
		}
	}
	return fmt.Errorf("刷新配额标记失败（用户 %d）：并发调整过于频繁，未能稳定写入", id)
}
