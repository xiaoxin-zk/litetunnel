package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type GroupExpiry struct {
	Set   bool
	Value *time.Time
}

func (s *Services) AdminSetUserGroup(id, groupID uint, expiry GroupExpiry) error {
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, groupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
			}
			return err
		}

		updates := map[string]any{"group_id": groupID}
		if expiry.Set {
			if expiry.Value == nil {
				updates["group_expire_at"] = nil
			} else {
				updates["group_expire_at"] = *expiry.Value
			}
		}
		res := tx.Model(&model.User{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		effective := &g
		expireAt := u.GroupExpireAt
		if expiry.Set {
			expireAt = expiry.Value
		}
		if expireAt != nil && !expireAt.After(time.Now()) {
			if dg := s.defaultGroupTx(tx); dg != nil {
				effective = dg
			}
		}
		return tx.Model(&model.Tunnel{}).Where("user_id = ?", id).
			Update("bandwidth_limit", effective.BandwidthLimit).Error
	})
	if err != nil {
		return err
	}

	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

func (s *Services) ListGroups() ([]model.Group, error) {
	var list []model.Group
	err := s.DB.Order("priority desc, id asc").Find(&list).Error
	return list, err
}

type GroupInput struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	MaxTunnels          int    `json:"max_tunnels"`
	MaxPorts            int    `json:"max_ports"`
	TrafficQuota        int64  `json:"traffic_quota"`
	BandwidthLimit      int64  `json:"bandwidth_limit"`
	AllowProtocols      string `json:"allow_protocols"`
	AllowCustomDomain   bool   `json:"allow_custom_domain"`
	AllowPrivilegedPort bool   `json:"allow_privileged_port"`
	Priority            int    `json:"priority"`
}

func (in *GroupInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 32 {
		return fmt.Errorf("%w: 分组名称需为 1-32 个字符", ErrInvalidParam)
	}
	if in.MaxTunnels < 0 || in.MaxPorts < 0 || in.TrafficQuota < 0 || in.BandwidthLimit < 0 {
		return fmt.Errorf("%w: 数值不能为负数", ErrInvalidParam)
	}
	allowed := map[string]bool{"tcp": true, "udp": true, "http": true, "https": true}
	parts := strings.Split(strings.ToLower(in.AllowProtocols), ",")
	cleaned := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !allowed[p] {
			return fmt.Errorf("%w: 不支持的协议 %q", ErrInvalidParam, p)
		}
		if !seen[p] {
			seen[p] = true
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("%w: 至少需要允许一种协议", ErrInvalidParam)
	}
	in.AllowProtocols = strings.Join(cleaned, ",")
	return nil
}

func (s *Services) CreateGroup(in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	g := &model.Group{
		Name:                in.Name,
		Description:         truncate(in.Description, 200),
		MaxTunnels:          in.MaxTunnels,
		MaxPorts:            in.MaxPorts,
		TrafficQuota:        in.TrafficQuota,
		BandwidthLimit:      in.BandwidthLimit,
		AllowProtocols:      in.AllowProtocols,
		AllowCustomDomain:   in.AllowCustomDomain,
		AllowPrivilegedPort: in.AllowPrivilegedPort,
		Priority:            in.Priority,
	}
	if err := s.DB.Create(g).Error; err != nil {
		return nil, fmt.Errorf("分组名称可能已存在: %w", err)
	}
	return g, nil
}

func (s *Services) UpdateGroup(id uint, in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var g model.Group
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		updates := map[string]any{
			"name":                  in.Name,
			"description":           truncate(in.Description, 200),
			"max_tunnels":           in.MaxTunnels,
			"max_ports":             in.MaxPorts,
			"traffic_quota":         in.TrafficQuota,
			"bandwidth_limit":       in.BandwidthLimit,
			"allow_protocols":       in.AllowProtocols,
			"allow_custom_domain":   in.AllowCustomDomain,
			"allow_privileged_port": in.AllowPrivilegedPort,
			"priority":              in.Priority,
		}
		res := tx.Model(&model.Group{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		now := time.Now()
		if err := tx.Model(&model.Tunnel{}).
			Where("user_id IN (?)", tx.Model(&model.User{}).
				Select("id").
				Where("group_id = ? AND (group_expire_at IS NULL OR group_expire_at > ?)", id, now)).
			Update("bandwidth_limit", in.BandwidthLimit).Error; err != nil {
			return err
		}
		fallback := in.BandwidthLimit
		if dg := s.defaultGroupTx(tx); dg != nil {
			fallback = dg.BandwidthLimit
		}
		return tx.Model(&model.Tunnel{}).
			Where("user_id IN (?)", tx.Model(&model.User{}).
				Select("id").
				Where("group_id = ? AND group_expire_at IS NOT NULL AND group_expire_at <= ?", id, now)).
			Update("bandwidth_limit", fallback).Error
	})
	if err != nil {
		return nil, err
	}
	if err := s.DB.First(&g, id).Error; err != nil {
		return nil, err
	}

	s.Runtime.BumpGuardVer()
	if err := s.refreshQuotaForGroup(id); err != nil {
		return &g, fmt.Errorf("分组已更新，但配额标记刷新失败（本组用户将沿用旧标记，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	return &g, nil
}

func (s *Services) refreshQuotaForGroup(groupID uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		var users []model.User
		if err := s.DB.Preload("Group").Where("group_id = ?", groupID).Find(&users).Error; err != nil {
			return fmt.Errorf("刷新分组 %d 的配额标记失败: %w", groupID, err)
		}
		stable := true
		for i := range users {
			s.EnsureTrafficPeriod(&users[i])
			if !s.Runtime.SetQuotaExceededIfVer(users[i].ID, s.QuotaExceeded(&users[i]), ver) {
				stable = false
				break
			}
		}
		if stable {
			return nil
		}
	}
	return fmt.Errorf("刷新分组 %d 的配额标记失败：并发调整过于频繁，未能稳定写入", groupID)
}

func (s *Services) DeleteGroup(id uint) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if g.IsDefault {
			return fmt.Errorf("%w: 默认分组不允许删除", ErrInvalidParam)
		}
		var used int64
		if err := tx.Model(&model.User{}).Where("group_id = ?", id).Count(&used).Error; err != nil {
			return err
		}
		if used > 0 {
			return fmt.Errorf("%w: 仍有 %d 个用户属于该分组，请先迁移", ErrInvalidParam, used)
		}
		var pending int64
		if err := tx.Model(&model.RedeemCode{}).
			Where("group_id = ? AND status = ?", id, model.RedeemStatusUnused).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return fmt.Errorf("%w: 还有 %d 张指向该分组的未核销升级码，请先停用或删除它们",
				ErrInvalidParam, pending)
		}
		res := tx.Delete(&model.Group{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}
