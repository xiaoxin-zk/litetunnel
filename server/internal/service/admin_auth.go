package service

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) AdminAuthenticate(username, password, totpCode, ip string) (*model.Admin, error) {
	username = strings.TrimSpace(username)
	var a model.Admin
	err := s.DB.Where("username = ?", username).First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		auth.VerifyPassword("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin", password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if !auth.VerifyPassword(a.Password, password) {
		return nil, ErrBadCredentials
	}
	if a.Status != "active" {
		return nil, ErrAccountDisabled
	}

	if a.TOTPEnabled {
		if strings.TrimSpace(totpCode) == "" {
			return nil, ErrTOTPRequired
		}
		step, ok := auth.VerifyTOTPStep(a.TOTPSecret, totpCode, time.Now())
		if !ok {
			return nil, ErrTOTPInvalid
		}
		if !s.ClaimTOTPStep(a.ID, step) {
			return nil, ErrTOTPReplay
		}
		now := time.Now()
		if err := s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
			Update("totp_verified_at", now).Error; err != nil {
			log.Printf("[admin] 记录管理员 %d 的 TOTP 验证时间失败（认证已通过，审计字段未更新）: %v", a.ID, err)
			s.recordAuditFailure(auditScopeAdminTOTP, err)
		} else {
			a.TOTPVerifiedAt = &now
		}
	}

	now := time.Now()
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
		Updates(map[string]any{"last_login_at": now, "last_login_ip": ip}).Error; err != nil {
		log.Printf("[admin] 记录管理员 %d 的登录时间/IP 失败（登录已通过，审计字段未更新）: %v", a.ID, err)
		s.recordAuditFailure(auditScopeAdminLogin, err)
	} else {
		a.LastLoginAt = &now
		a.LastLoginIP = ip
	}
	return &a, nil
}

func (s *Services) AdminTOTPSetup(id uint, code string) (secret, otpauthURL string, err error) {
	var username, generated string
	err = s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		username = a.Username
		if a.TOTPEnabled {
			if strings.TrimSpace(code) == "" {
				return false, fmt.Errorf(
					"%w: 双因素认证已启用，换绑需要输入当前动态口令（设备已丢失请联系超级管理员重置）",
					ErrInvalidParam)
			}
			step, ok := auth.VerifyTOTPStep(a.TOTPSecret, code, time.Now())
			if !ok {
				return false, ErrTOTPInvalid
			}
			if !s.ClaimTOTPStepTx(tx, a.ID, step) {
				return false, ErrTOTPReplay
			}
		}

		var gerr error
		generated, gerr = auth.GenerateTOTPSecret()
		if gerr != nil {
			return false, gerr
		}
		if err := tx.Model(&model.Admin{}).Where("id = ?", id).
			Update("totp_pending_secret", generated).Error; err != nil {
			return false, err
		}
		return false, nil
	})
	if err != nil {
		return "", "", err
	}
	return generated, auth.OtpauthURL("LiteTunnel", username, generated), nil
}

func (s *Services) AdminTOTPEnable(id uint, code string) error {
	return s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		pending := a.TOTPPendingSecret
		target := pending
		if target == "" {
			target = a.TOTPSecret
		}
		if target == "" {
			return false, fmt.Errorf("%w: 请先生成密钥", ErrInvalidParam)
		}

		step, ok := auth.VerifyTOTPStep(target, code, time.Now())
		if !ok {
			return false, ErrTOTPInvalid
		}
		now := time.Now()

		if pending != "" {
			res := tx.Model(&model.Admin{}).
				Where("id = ? AND totp_pending_secret = ?", id, pending).
				Updates(map[string]any{
					"totp_secret":         pending,
					"totp_pending_secret": "",
					"totp_enabled":        true,
					"totp_last_step":      step,
					"totp_verified_at":    now,
					"token_version":       gorm.Expr("token_version + 1"),
				})
			if res.Error != nil {
				return false, res.Error
			}
			if res.RowsAffected == 0 {
				return false, ErrTOTPReplay
			}
			return true, nil
		}

		if !s.ClaimTOTPStepTx(tx, a.ID, step) {
			return false, ErrTOTPReplay
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled":     true,
			"totp_verified_at": now,
		})
	})
}

func (s *Services) withAdminSecurity(id uint, fn func(tx *gorm.DB, a *model.Admin) (bool, error)) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	var changed bool
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		c, ferr := fn(tx, &a)
		changed = c
		return ferr
	})
	if err != nil {
		return err
	}
	if changed {
		s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	}
	return nil
}

func (s *Services) updateAdminSecurityTx(tx *gorm.DB, id uint, updates map[string]any) error {
	updates["token_version"] = gorm.Expr("token_version + 1")
	return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error
}

func (s *Services) AdminTOTPDisable(id uint, password string) error {
	err := s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		if !auth.VerifyPassword(a.Password, password) {
			return false, fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
		}
		if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
			return false, nil
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled":        false,
			"totp_secret":         "",
			"totp_pending_secret": "",
		})
	})
	if err != nil {
		return err
	}
	s.DropStepUpGrant(id)
	return nil
}

func (s *Services) AdminChangePassword(id uint, oldPassword, newPassword string) error {
	if len(newPassword) < 12 {
		return fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
	}
	if newPassword == oldPassword {
		return fmt.Errorf("%w: 新密码不能与原密码相同", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if !auth.VerifyPassword(a.Password, oldPassword) {
			return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
		}
		return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error
	})
	if err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	s.DropStepUpGrant(id)
	return nil
}

func (s *Services) AdminClearTOTP(id uint) error {
	err := s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
			return false, nil
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled":        false,
			"totp_secret":         "",
			"totp_pending_secret": "",
			"totp_verified_at":    nil,
		})
	})
	if err != nil {
		return err
	}
	s.DropStepUpGrant(id)
	return nil
}
