package service

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type TunnelInput struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	LocalIP        string `json:"local_ip"`
	LocalPort      int    `json:"local_port"`
	RemotePort     int    `json:"remote_port"`
	Domain         string `json:"domain"`
	Subdomain      string `json:"subdomain"`
	Remark         string `json:"remark"`
	UseEncryption  bool   `json:"use_encryption"`
	UseCompression bool   `json:"use_compression"`
}

func (s *Services) ListTunnels(userID uint) ([]model.Tunnel, error) {
	list, _, _, err := s.ListTunnelsPage(userID, 0, 0)
	return list, err
}

func (s *Services) ListTunnelsPage(userID, beforeID uint, limit int) (list []model.Tunnel, total int64, version string, err error) {
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").Error; err != nil {
				return err
			}
		}

		q := tx.Where("user_id = ?", userID).Order("id desc")
		if beforeID > 0 {
			q = q.Where("id < ?", beforeID)
		}
		if limit > 0 {
			q = q.Limit(limit)
		}
		if err := q.Find(&list).Error; err != nil {
			return err
		}

		v, n, verr := s.tunnelListVersionTx(tx, userID)
		if verr != nil {
			return verr
		}
		version, total = v, n
		return nil
	})
	if err != nil {
		return nil, 0, "", err
	}
	return list, total, version, nil
}

func (s *Services) tunnelListVersionTx(tx *gorm.DB, userID uint) (string, int64, error) {
	var revs []int64
	if err := tx.Model(&model.TunnelListRev{}).
		Where("user_id = ?", userID).Pluck("rev", &revs).Error; err != nil {
		return "", 0, err
	}
	var rev int64
	if len(revs) > 0 {
		rev = revs[0]
	}

	var total int64
	if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%d:%d", total, rev), total, nil
}

func (s *Services) GetTunnel(userID, id uint) (*model.Tunnel, error) {
	var t model.Tunnel
	err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Services) FindTunnelByName(userID uint, name string) (*model.Tunnel, error) {
	var t model.Tunnel
	err := s.DB.Where("user_id = ? AND name = ?", userID, name).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Services) CreateTunnel(u *model.User, in TunnelInput) (*model.Tunnel, error) {
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	attempts := 1
	if in.RemotePort == 0 {
		attempts = portAllocAttempts
	}

	var (
		created *model.Tunnel
		err     error
	)
	for attempt := 1; attempt <= attempts; attempt++ {
		created, err = s.createTunnelLocked(u, in, true)
		if err == nil {
			return created, nil
		}
		if !isPortConflict(err) {
			return nil, describeTunnelWriteError(err)
		}
		log.Printf("[tunnel] 端口分配撞车（第 %d/%d 次尝试），重新随机分配后重试", attempt, attempts)
	}
	return nil, describeTunnelWriteError(err)
}

func (s *Services) reloadUserWithGroupTx(tx *gorm.DB, userID uint) (*model.User, *model.Group, error) {
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	g, err := s.effectiveGroupTx(tx, &u)
	if err != nil {
		return nil, nil, err
	}
	return &u, g, nil
}

func (s *Services) effectiveGroupTx(tx *gorm.DB, u *model.User) (*model.Group, error) {
	if u.GroupExpireAt != nil && u.GroupExpireAt.Before(time.Now()) {
		return s.defaultGroupTx(tx), nil
	}
	if u.GroupID == 0 {
		return s.defaultGroupTx(tx), nil
	}
	var g model.Group
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&g, u.GroupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return s.defaultGroupTx(tx), nil
		}
		return nil, err
	}
	return &g, nil
}

func (s *Services) defaultGroupTx(tx *gorm.DB) *model.Group {
	var g model.Group
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

func (s *Services) createTunnelLocked(u *model.User, in TunnelInput, firewallNow bool) (*model.Tunnel, error) {
	var created model.Tunnel

	port := 0
	if isPortTunnelType(in.Type) {
		port = in.RemotePort
		if port == 0 {
			p, err := s.allocatePort(s.DB, u.ID)
			if err != nil {
				return nil, err
			}
			port = p
		}
	}

	var portUnlock func()
	if port > 0 {
		pl := s.portLock(port)
		pl.Lock()
		portUnlock = pl.Unlock
	}
	defer func() {
		if portUnlock != nil {
			portUnlock()
		}
	}()

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		u, g, err := s.reloadUserWithGroupTx(tx, u.ID)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.New("当前账号未绑定任何分组，请联系管理员")
		}

		normalized, err := s.normalizeInput(u, g, in)
		if err != nil {
			return err
		}

		var count int64
		if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil {
			return err
		}
		if g.MaxTunnels > 0 && count >= int64(g.MaxTunnels) {
			return ErrTunnelLimit
		}

		if normalized.Type == model.ProxyTypeTCP || normalized.Type == model.ProxyTypeUDP {
			if g.MaxPorts > 0 {
				var portCount int64
				if err := tx.Model(&model.Tunnel{}).
					Where("user_id = ? AND remote_port > 0", u.ID).Count(&portCount).Error; err != nil {
					return err
				}
				if portCount >= int64(g.MaxPorts) {
					return ErrPortLimit
				}
			}
			if err := s.assertPortFree(tx, port); err != nil {
				return err
			}
			normalized.RemotePort = port
		} else {
			normalized.RemotePort = 0
		}

		normalized.UserID = u.ID
		normalized.BandwidthLimit = g.BandwidthLimit
		if err := tx.Create(&normalized).Error; err != nil {
			return err
		}
		created = normalized
		return nil
	})
	if err != nil {
		return nil, err
	}

	if firewallNow && created.RemotePort > 0 {
		if _, ferr := s.applyPortIntentLocked(created.RemotePort, ProtoOfTunnel(created.Type), true); errors.Is(ferr, ErrFirewallQueueFull) || errors.Is(ferr, ErrFirewallQueueUnavailable) {
			return &created, fmt.Errorf("隧道已创建，但防火墙放行失败且无法自动重试：%w", ferr)
		}
	}
	return &created, nil
}

func isPortTunnelType(tunnelType string) bool {
	switch strings.ToLower(strings.TrimSpace(tunnelType)) {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		return true
	}
	return false
}

func (s *Services) UpdateTunnel(u *model.User, id uint, in TunnelInput) (*model.Tunnel, error) {
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	t, err := s.GetTunnel(u.ID, id)
	if err != nil {
		return nil, err
	}

	if in.LocalPort < 1 || in.LocalPort > 65535 {
		return nil, fmt.Errorf("%w: 本地端口需在 1-65535 之间", ErrInvalidParam)
	}
	localIP := strings.TrimSpace(in.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil && !isValidHostname(localIP) {
		return nil, fmt.Errorf("%w: 本地地址格式不正确", ErrInvalidParam)
	}

	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		u, g, err := s.reloadUserWithGroupTx(tx, u.ID)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.New("当前账号未绑定任何分组，请联系管理员")
		}

		updates := map[string]any{
			"local_ip":        localIP,
			"local_port":      in.LocalPort,
			"remark":          truncate(in.Remark, 200),
			"use_encryption":  in.UseEncryption,
			"use_compression": in.UseCompression,
		}
		if t.Type == model.ProxyTypeHTTP || t.Type == model.ProxyTypeHTTPS {
			domain, sub, err := s.normalizeDomain(g, in)
			if err != nil {
				return err
			}
			updates["domain"] = domain
			updates["subdomain"] = sub
		}

		res := tx.Model(&model.Tunnel{}).
			Where("id = ? AND user_id = ?", id, u.ID).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.GetTunnel(u.ID, id)
}

func (s *Services) DeleteTunnel(userID, id uint) error {
	_, err := s.DeleteTunnelResult(userID, id)
	return err
}

func (s *Services) DeleteTunnelResult(userID, id uint) (TunnelMutationResult, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	var t model.Tunnel
	if err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}

	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Tunnel{})
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

func (s *Services) SetTunnelStatus(userID, id uint, status string) error {
	_, err := s.SetTunnelStatusResult(userID, id, status)
	return err
}

func (s *Services) SetTunnelStatusResult(userID, id uint, status string) (TunnelMutationResult, error) {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return TunnelMutationResult{}, ErrInvalidParam
	}

	var t model.Tunnel
	if err := s.DB.Where("id = ? AND user_id = ?", id, userID).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}
	return s.setTunnelStatusResult(&t, status)
}

func (s *Services) assertTunnelCanEnable(t *model.Tunnel, status string) error {
	if status != model.TunnelStatusActive || t.Type != model.ProxyTypeHTTPS {
		return nil
	}
	if !s.HTTPSProxyEntryEnabled() {
		return ErrNoHTTPSProxyEntry
	}
	return nil
}

func (s *Services) setTunnelStatus(t *model.Tunnel, status string) error {
	_, err := s.setTunnelStatusResult(t, status)
	return err
}

func (s *Services) setTunnelStatusResult(t *model.Tunnel, status string) (TunnelMutationResult, error) {
	lock := s.userLock(t.UserID)
	lock.Lock()
	defer lock.Unlock()

	var cur model.Tunnel
	if err := s.DB.First(&cur, t.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}
	t = &cur

	if err := s.assertTunnelCanEnable(t, status); err != nil {
		return TunnelMutationResult{}, err
	}

	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.Tunnel{}).Where("id = ?", t.ID).Update("status", status)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if t.RemotePort <= 0 {
			return nil
		}
		open := status == model.TunnelStatusActive
		gen, err := firewallIntentTx(tx, t.RemotePort, ProtoOfTunnel(t.Type), open)
		if err != nil {
			return err
		}
		intents = append(intents, portIntent{
			port: t.RemotePort, proto: ProtoOfTunnel(t.Type), open: open, gen: gen,
		})
		return nil
	})
	if err != nil {
		return TunnelMutationResult{}, err
	}

	pending, fatal, warnings := s.executePortIntentsAfterCommit(intents)
	res := tunnelMutationResult(pending, warnings)
	if status != model.TunnelStatusActive {
		return res, nil
	}
	if fatal != nil {
		return res, fmt.Errorf("隧道已启用，但防火墙放行失败且无法自动重试：%w", fatal)
	}
	return res, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size != 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut
}
