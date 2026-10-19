package service

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type emailCodePayload struct {
	Email        string `json:"email"`
	Scene        string `json:"scene"`
	CodeHash     string `json:"code_hash"`
	TTLSeconds   int    `json:"ttl_seconds"`
	IP           string `json:"ip"`
	TokenVersion *int   `json:"token_version,omitempty"`
}

type resetLinkPayload struct {
	UserID       uint   `json:"user_id"`
	TokenHash    string `json:"token_hash"`
	TTLSeconds   int    `json:"ttl_seconds"`
	IP           string `json:"ip"`
	TokenVersion *int   `json:"token_version,omitempty"`
}

var errMailActionSuperseded = errors.New("已被更新的凭据取代")

var errMailActionObsolete = errors.New("目标账号已不存在，凭据动作作废")

func (s *Services) applyMailAction(row model.MailOutbox, token string) error {
	switch row.Kind {
	case model.MailKindEmailCodeRegister, model.MailKindEmailCodeReset, model.MailKindEmailCodeChange:
		return s.activateEmailCode(row, token)
	case model.MailKindResetLink:
		return s.activateResetToken(row, token)
	default:
		return nil
	}
}

// mailKindHasAction 表示这类邮件送达后还需要在库里激活某个凭据。
// 告警与报告只是通知，送达即终态。
func mailKindHasAction(kind string) bool {
	switch kind {
	case model.MailKindEmailCodeRegister, model.MailKindEmailCodeReset,
		model.MailKindEmailCodeChange, model.MailKindResetLink:
		return true
	default:
		return false
	}
}

func stillClaimed(tx *gorm.DB, rowID uint, token string) error {
	var n int64
	if err := tx.Model(&model.MailOutbox{}).
		Where("id = ? AND status = ? AND claim_token = ?", rowID, model.MailActivating, token).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return errMailActionObsolete
	}
	return nil
}

func (s *Services) activateEmailCode(row model.MailOutbox, token string) error {
	var p emailCodePayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	if p.TTLSeconds <= 0 {
		return errors.New("验证码缺少有效期参数")
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := stillClaimed(tx, row.ID, token); err != nil {
			return err
		}

		if p.Scene == EmailSceneReset {
			var u model.User
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("lower(email) = ?", strings.ToLower(row.To)).
				First(&u).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errMailActionObsolete
			}
			if err != nil {
				return err
			}
			if !u.EmailVerified {
				return errMailActionObsolete
			}
			if p.TokenVersion == nil {
				if u.TokenVersion > 1 {
					return errMailActionObsolete
				}
			} else if u.TokenVersion != *p.TokenVersion {
				return errMailActionObsolete
			}
		}

		var activated int64
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND code_hash = ? AND (mail_id = ? OR used_at IS NULL)",
				p.Email, p.Scene, p.CodeHash, row.ID).
			Count(&activated).Error; err != nil {
			return err
		}
		if activated > 0 {
			return nil
		}
		if err := s.lockAdvisory(tx, "emailcode:"+p.Email+":"+p.Scene); err != nil {
			return err
		}

		var newer int64
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND mail_id > ?", p.Email, p.Scene, row.ID).
			Count(&newer).Error; err != nil {
			return err
		}
		if newer > 0 {
			return errMailActionSuperseded
		}
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND used_at IS NULL", p.Email, p.Scene).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.EmailCode{
			Email:    p.Email,
			Scene:    p.Scene,
			CodeHash: p.CodeHash,
			ExpireAt: time.Now().Add(time.Duration(p.TTLSeconds) * time.Second),
			IP:       p.IP,
			MailID:   row.ID,
		}).Error
	})
}

func (s *Services) activateResetToken(row model.MailOutbox, token string) error {
	var p resetLinkPayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	if p.TTLSeconds <= 0 {
		return errors.New("重置令牌缺少有效期参数")
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := stillClaimed(tx, row.ID, token); err != nil {
			return err
		}

		var u model.User
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, p.UserID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errMailActionObsolete
		}
		if err != nil {
			return err
		}
		if !u.EmailVerified || !strings.EqualFold(u.Email, row.To) {
			return errMailActionObsolete
		}
		if p.TokenVersion == nil {
			if u.TokenVersion > 1 {
				return errMailActionObsolete
			}
		} else if u.TokenVersion != *p.TokenVersion {
			return errMailActionObsolete
		}
		var activated int64
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND token_hash = ? AND (mail_id = ? OR used_at IS NULL)",
				p.UserID, p.TokenHash, row.ID).
			Count(&activated).Error; err != nil {
			return err
		}
		if activated > 0 {
			return nil
		}
		var newer int64
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND mail_id > ?", p.UserID, row.ID).
			Count(&newer).Error; err != nil {
			return err
		}
		if newer > 0 {
			return errMailActionSuperseded
		}
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND used_at IS NULL", p.UserID).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.PasswordResetToken{
			UserID:    p.UserID,
			TokenHash: p.TokenHash,
			ExpireAt:  time.Now().Add(time.Duration(p.TTLSeconds) * time.Second),
			IP:        p.IP,
			MailID:    row.ID,
		}).Error
	})
}
