package service

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) UpdatePassword(userID uint, oldPwd, newPwd string) error {
	if len(newPwd) < 8 {
		return fmt.Errorf("%w: 新密码长度不得少于 8 位", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPwd)
	if err != nil {
		return err
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&locked, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if !auth.VerifyPassword(locked.Password, oldPwd) {
			return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
		}
		if auth.VerifyPassword(locked.Password, newPwd) {
			return fmt.Errorf("%w: 新密码不能与当前密码相同", ErrInvalidParam)
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error; err != nil {
			return err
		}
		if err := revokeClientSessionsTx(tx, userID); err != nil {
			return err
		}
		return revokePasswordResetTx(tx, userID, locked.Email)
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	s.Runtime.DropUserSessions(userID)
	return nil
}
