package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

const (
	maxRedeemTrafficValue  = int64(1) << 50
	maxRedeemBalanceValue  = int64(10_000_000_00)
	maxRedeemDurationValue = int64(36500)
)

type GenerateCodesInput struct {
	Count    int        `json:"count"`
	Type     string     `json:"type"`
	Value    int64      `json:"value"`
	GroupID  uint       `json:"group_id"`
	MaxUses  int        `json:"max_uses"`
	ExpireAt *time.Time `json:"expire_at"`
	Remark   string     `json:"remark"`
}

type RedeemResult struct {
	Type    string `json:"type"`
	Value   int64  `json:"value"`
	Message string `json:"message"`
}

func (s *Services) Redeem(userID uint, code, ip string) (*RedeemResult, error) {
	code = normalizeCode(code)
	if code == "" {
		return nil, ErrCodeInvalid
	}

	var result RedeemResult
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var c model.RedeemCode
		err := tx.Where("code = ?", code).First(&c).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrCodeInvalid
		}
		if err != nil {
			return err
		}

		switch c.Status {
		case model.RedeemStatusDisabled:
			return ErrCodeDisabled
		case model.RedeemStatusUsedUp:
			return ErrCodeUsed
		}
		if c.ExpireAt != nil && c.ExpireAt.Before(time.Now()) {
			return ErrCodeExpired
		}
		if c.MaxUses > 0 && c.UsedCount >= c.MaxUses {
			return ErrCodeUsed
		}

		claim := tx.Model(&model.RedeemCode{}).
			Where("id = ? AND status = ? AND (max_uses <= 0 OR used_count < max_uses)",
				c.ID, model.RedeemStatusUnused).
			Update("used_count", gorm.Expr("used_count + 1"))
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected == 0 {
			return ErrCodeUsed
		}

		if err := tx.Model(&model.RedeemCode{}).
			Where("id = ? AND max_uses > 0 AND used_count >= max_uses", c.ID).
			Update("status", model.RedeemStatusUsedUp).Error; err != nil {
			return err
		}

		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, userID).Error; err != nil {
			return ErrNotFound
		}

		updates := map[string]any{}
		switch c.Type {
		case model.RedeemTypeTraffic:
			base := u.TrafficQuota
			if base == 0 {
				base = s.effectiveGroupQuotaTx(tx, &u)
			}
			if c.Value > math.MaxInt64-base {
				return fmt.Errorf("%w: 流量额度已达上限，无法再兑换这张码", ErrCodeInvalid)
			}
			updates["traffic_quota"] = base + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("流量额度已增加 %s", FormatBytes(c.Value))}

		case model.RedeemTypeBalance:
			if c.Value > math.MaxInt64-u.Balance {
				return fmt.Errorf("%w: 余额已达上限，无法再兑换这张码", ErrCodeInvalid)
			}
			updates["balance"] = u.Balance + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("余额已增加 %.2f 元", float64(c.Value)/100)}

		case model.RedeemTypeGroup:
			var g model.Group
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&g, c.GroupID).Error; err != nil {
				return ErrCodeInvalid
			}
			now := time.Now()
			if u.GroupExpireAt != nil && !u.GroupExpireAt.After(now) {
				return fmt.Errorf("%w（%s），请先兑换时长码再兑换本分组码",
					ErrMembershipExpired, u.GroupExpireAt.Format("2006-01-02"))
			}

			updates["group_id"] = g.ID
			if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", u.ID).
				Update("bandwidth_limit", g.BandwidthLimit).Error; err != nil {
				return err
			}
			msg := fmt.Sprintf("已升级到分组「%s」", g.Name)
			if u.GroupExpireAt == nil {
				msg += "（当前无有效期限制；如需设有效期可兑换时长码）"
			} else {
				msg += fmt.Sprintf("，有效期至 %s（到期后回落默认分组，可兑换时长码延长）",
					u.GroupExpireAt.Format("2006-01-02"))
			}
			result = RedeemResult{Type: c.Type, Value: int64(g.ID), Message: msg}

		case model.RedeemTypeDuration:
			base := time.Now()
			if u.GroupExpireAt != nil && u.GroupExpireAt.After(base) {
				base = *u.GroupExpireAt
			}
			next := base.AddDate(0, 0, int(c.Value))
			updates["group_expire_at"] = next
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("分组有效期已延长 %d 天，有效期至 %s",
					c.Value, next.Format("2006-01-02"))}

		default:
			return ErrCodeInvalid
		}

		if err := tx.Model(&model.User{}).Where("id = ?", u.ID).Updates(updates).Error; err != nil {
			return err
		}

		return s.recordRedeem(tx, userID, c.ID, code, c.Type, c.Value, "success", ip)
	})
	if err != nil {
		if errors.Is(err, ErrCodeInvalid) {
			if e := s.recordRedeem(s.DB, userID, 0, code, "", 0, "invalid", ip); e != nil {
				log.Printf("[redeem] 记录无效兑换码尝试失败（用户 %d，码 %q）: %v", userID, code, e)
				s.recordAuditFailure(auditScopeRedeemInvalid, e)
			}
		}
		return nil, err
	}

	s.Runtime.BumpGuardVer()
	if err := s.refreshQuotaFor(userID); err != nil {
		log.Printf("[redeem] 兑换已成功（用户 %d），但配额标记刷新失败，用户可能要等下一轮采集才能解除拦截: %v", userID, err)
	}
	return &result, nil
}

func (s *Services) effectiveGroupQuotaTx(tx *gorm.DB, u *model.User) int64 {
	expired := u.GroupExpireAt != nil && !u.GroupExpireAt.After(time.Now())
	if !expired && u.GroupID != 0 {
		var g model.Group
		if err := tx.First(&g, u.GroupID).Error; err == nil {
			return g.TrafficQuota
		}
	}
	var def model.Group
	if err := tx.Where("is_default = ?", true).First(&def).Error; err == nil {
		return def.TrafficQuota
	}
	return 0
}

func (s *Services) recordRedeem(tx *gorm.DB, userID, codeID uint, code, rtype string, value int64, result, ip string) error {
	return tx.Create(&model.RedeemRecord{
		UserID: userID,
		CodeID: codeID,
		Code:   code,
		Type:   rtype,
		Value:  value,
		Result: result,
		IP:     ip,
	}).Error
}

func newCode() (string, error) {
	groups := make([]string, 3)
	for g := 0; g < 3; g++ {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		var sb strings.Builder
		for _, b := range buf {
			sb.WriteByte(codeAlphabet[int(b)%len(codeAlphabet)])
		}
		groups[g] = sb.String()
	}
	return "LT-" + strings.Join(groups, "-"), nil
}

func normalizeCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "LT-") {
		if len(s) == 12 {
			s = "LT-" + s[:4] + "-" + s[4:8] + "-" + s[8:]
		}
	}
	return s
}
