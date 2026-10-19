package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func accountPurgeTx(tx *gorm.DB, userID uint, verify func(u *model.User) error) ([]portIntent, error) {
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if verify != nil {
		if err := verify(&u); err != nil {
			return nil, err
		}
	}

	var tunnels []model.Tunnel
	if err := tx.Where("user_id = ? AND remote_port > 0", userID).Find(&tunnels).Error; err != nil {
		return nil, err
	}
	ports := portsOfTunnels(tunnels)

	if err := tx.Where("user_id = ?", userID).Delete(&model.Tunnel{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.TunnelListRev{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficDaily{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.ClientSession{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficResetMark{}).Error; err != nil {
		return nil, err
	}
	if err := purgeAccountCredentialsTx(tx, userID, u.Email); err != nil {
		return nil, err
	}

	intents, err := recordPurgeIntentsTx(tx, userID, u.Incarnation, ports)
	if err != nil {
		return nil, err
	}

	if err := tx.Delete(&model.User{}, userID).Error; err != nil {
		return nil, err
	}
	return intents, nil
}

func recordPurgeIntentsTx(tx *gorm.DB, userID uint, incarnation string, ports []portProto) ([]portIntent, error) {
	now := time.Now()
	fence, ferr := randomHex(16)
	if ferr != nil {
		return nil, fmt.Errorf("生成断流围栏令牌失败，已回滚本次删除: %w", ferr)
	}
	pending := model.ProxyDrainPending{
		UserID:      userID,
		Incarnation: incarnation,
		Prefix:      FrpUserOf(userID) + ".",
		StatusGen:   0,
		NotAfter:    0,
		Deleted:     true,
		Fence:       fence,
		IntentAt:    now.Unix(),
		NextAt:      now,
	}
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"incarnation", "prefix", "status_gen", "not_after", "deleted", "intent_at", "next_at", "attempts", "exhausted", "fence", "last_err"}),
	}).Create(&pending).Error; err != nil {
		return nil, fmt.Errorf("登记断流待办失败，已回滚本次删除: %w", err)
	}

	var intents []portIntent
	for _, p := range ports {
		if p.port <= 0 {
			continue
		}
		gen, err := firewallIntentTx(tx, p.port, p.proto, false)
		if err != nil {
			return nil, err
		}
		intents = append(intents, portIntent{port: p.port, proto: p.proto, open: false, gen: gen})
	}
	return intents, nil
}

func (s *Services) purgeAccountAfterCommit(userID uint, intents []portIntent) {
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(userID, false)
	s.Runtime.SetUserBlocked(userID, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	s.forgetUserStatusGen(userID)
	s.Runtime.DropUserSessions(userID)

	s.closeUserProxiesAfterDelete(userID)
	if pending, fatal, warnings := s.executePortIntentsAfterCommit(intents); pending > 0 {
		if fatal != nil {
			log.Printf("[user] 删除用户 %d 后有 %d 个端口规则未能收回且无法自动重试（%v），需手工关闭：%s",
				userID, pending, fatal, firewallPendingWarning(warnings, pending))
		} else {
			log.Printf("[user] 删除用户 %d 后仍有 %d 个端口规则未收回，已进入重试队列：%s",
				userID, pending, firewallPendingWarning(warnings, pending))
		}
	}
}
