package service

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type ProfileUpdateInput struct {
	Username *string `json:"username"`
	Nickname *string `json:"nickname"`
	Email    *string `json:"email"`
}

func (s *Services) UpdateProfile(userID uint, in ProfileUpdateInput) (*model.User, error) {
	fields := map[string]any{}

	if in.Username != nil {
		name := strings.TrimSpace(*in.Username)
		if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
			return nil, fmt.Errorf("%w: 用户名需为 3-32 位字母、数字或下划线", ErrInvalidParam)
		}
		fields["username"] = name
	}

	if in.Nickname != nil {
		nick := strings.TrimSpace(*in.Nickname)
		if len([]rune(nick)) > 32 {
			return nil, fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
		}
		fields["nickname"] = nick
	}

	var email *string
	if in.Email != nil {
		e := strings.ToLower(strings.TrimSpace(*in.Email))
		if e != "" && !IsValidEmail(e) {
			return nil, fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		email = &e
	}

	if len(fields) == 0 && email == nil {
		return s.LoadUser(userID)
	}
	return s.updateProfileLocked(userID, profilePatch{
		email:                    email,
		requireEmailVerification: true,
		fields:                   fields,
	})
}

type profilePatch struct {
	email                    *string
	requireEmailVerification bool
	bumpTokenVersion         bool
	fields                   map[string]any
}

func (s *Services) updateProfileLocked(userID uint, p profilePatch) (*model.User, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	emailChanged := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var cur model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&cur, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		if p.email != nil {
			want := strings.ToLower(strings.TrimSpace(*p.email))
			if want != strings.ToLower(strings.TrimSpace(cur.Email)) {
				if p.requireEmailVerification && s.MailEnabled() {
					return fmt.Errorf("%w: 修改邮箱需要验证新地址，请使用「更换邮箱」流程", ErrInvalidParam)
				}
				if want != "" {
					var taken int64
					if err := tx.Model(&model.User{}).
						Where("lower(email) = ? AND id <> ?", want, userID).
						Count(&taken).Error; err != nil {
						return err
					}
					if taken > 0 {
						return ErrEmailTaken
					}
				}
				updates := map[string]any{
					"email":          want,
					"email_verified": false,
				}
				if p.bumpTokenVersion {
					updates["token_version"] = gorm.Expr("token_version + 1")
				}
				if err := tx.Model(&model.User{}).Where("id = ?", userID).
					Updates(updates).Error; err != nil {
					return err
				}
				if err := purgeEmailCredentialsTx(tx, userID, cur.Email); err != nil {
					return err
				}
				emailChanged = true
			}
		}

		if len(p.fields) == 0 {
			return nil
		}
		if name, ok := p.fields["username"]; ok {
			var taken int64
			if err := tx.Model(&model.User{}).
				Where("username = ? AND id <> ?", name, userID).
				Count(&taken).Error; err != nil {
				return err
			}
			if taken > 0 {
				return ErrUsernameTaken
			}
		}
		if res := tx.Model(&model.User{}).Where("id = ?", userID).
			Updates(p.fields); res.Error != nil {
			if isUniqueConflict(res.Error) {
				return ErrUsernameTaken
			}
			return res.Error
		}
		if name, ok := p.fields["username"]; ok {
			if err := tx.Model(&model.ClientSession{}).Where("user_id = ?", userID).
				Update("username", name).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if emailChanged && p.bumpTokenVersion {
		s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	}
	return s.LoadUser(userID)
}

func (s *Services) RequestEmailChange(userID uint, newEmail, password, ip string) error {
	u, err := s.LoadUser(userID)
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(u.Password, password) {
		return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
	}
	email := strings.ToLower(strings.TrimSpace(newEmail))
	if !IsValidEmail(email) {
		return ErrEmailRequired
	}
	if email == strings.ToLower(strings.TrimSpace(u.Email)) {
		return fmt.Errorf("%w: 新邮箱与当前邮箱相同", ErrInvalidParam)
	}
	return s.SendEmailCode(email, EmailSceneChange, ip)
}

func (s *Services) ConfirmEmailChange(userID uint, newEmail, code string) error {
	email := strings.ToLower(strings.TrimSpace(newEmail))
	if !IsValidEmail(email) {
		return ErrEmailRequired
	}

	rec, err := s.checkEmailCode(s.DB, email, EmailSceneChange, code)
	if err != nil {
		return err
	}

	return s.DB.Transaction(func(tx *gorm.DB) error {
		var old model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&old, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		var taken int64
		if err := tx.Model(&model.User{}).
			Where("lower(email) = ? AND id <> ?", email, userID).
			Count(&taken).Error; err != nil {
			return err
		}
		if taken > 0 {
			return ErrEmailTaken
		}

		if err := s.consumeEmailCode(tx, rec.ID); err != nil {
			return err
		}

		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
			"email":          email,
			"email_verified": true,
		}).Error; err != nil {
			return err
		}

		return purgeEmailCredentialsTx(tx, userID, old.Email)
	})
}
