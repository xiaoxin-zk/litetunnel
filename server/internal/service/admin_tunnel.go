package service

import (
	"errors"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) ListAllTunnels(keyword, status string, userID uint, offset, limit int) ([]model.Tunnel, int64, error) {
	q := s.DB.Model(&model.Tunnel{})
	if keyword != "" {
		q = q.Where("name LIKE ?", "%"+keyword+"%")
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.Tunnel
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

func (s *Services) AdminSetTunnelStatus(id uint, status string) error {
	_, err := s.AdminSetTunnelStatusResult(id, status)
	return err
}

func (s *Services) AdminSetTunnelStatusResult(id uint, status string) (TunnelMutationResult, error) {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return TunnelMutationResult{}, ErrInvalidParam
	}

	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}
	return s.setTunnelStatusResult(&t, status)
}

func (s *Services) AdminDeleteTunnel(id uint) error {
	_, err := s.AdminDeleteTunnelResult(id)
	return err
}

func (s *Services) AdminDeleteTunnelResult(id uint) (TunnelMutationResult, error) {
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}

	lock := s.userLock(t.UserID)
	lock.Lock()
	defer lock.Unlock()

	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}

	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ?", id).Delete(&model.Tunnel{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if t.RemotePort <= 0 {
			return nil
		}
		gen, err := firewallIntentTx(tx, t.RemotePort, ProtoOfTunnel(t.Type), false)
		if err != nil {
			return err
		}
		intents = append(intents, portIntent{
			port: t.RemotePort, proto: ProtoOfTunnel(t.Type), open: false, gen: gen,
		})
		return nil
	})
	if err != nil {
		return TunnelMutationResult{}, err
	}

	pending, fatal, warnings := s.executePortIntentsAfterCommit(intents)
	if fatal != nil {
		res := tunnelMutationResult(pending, warnings)
		res.Warning = "隧道已删除，但端口规则未能收回且无法自动重试（" +
			fatal.Error() + "），请手工关闭对应端口"
		return res, nil
	}
	return tunnelMutationResult(pending, warnings), nil
}

func (s *Services) ListClientSessions(userID uint, offset, limit int) ([]model.ClientSession, int64, error) {
	q := s.DB.Model(&model.ClientSession{})
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.ClientSession
	err := q.Order("last_seen_at desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}
