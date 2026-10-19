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

func (s *Services) LoadAdmin(id uint) (*model.Admin, error) {
	var a model.Admin
	if err := s.DB.First(&a, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

type AdminProfileInput struct {
	Username *string `json:"username"`
	Nickname *string `json:"nickname"`
}

func (s *Services) AdminUpdateProfile(id uint, in AdminProfileInput) (*model.Admin, error) {
	var result model.Admin
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		updates := map[string]any{}
		if in.Username != nil {
			name := strings.TrimSpace(*in.Username)
			if name != a.Username {
				if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
					return fmt.Errorf("%w: 登录账号需为 3-32 位字母、数字或下划线", ErrInvalidParam)
				}
				var n int64
				if err := tx.Model(&model.Admin{}).Where("username = ? AND id <> ?", name, id).Count(&n).Error; err != nil {
					return err
				}
				if n > 0 {
					return ErrUsernameTaken
				}
				updates["username"] = name
			}
		}
		if in.Nickname != nil {
			nick := strings.TrimSpace(*in.Nickname)
			if len([]rune(nick)) > 32 {
				return fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
			}
			updates["nickname"] = nick
		}

		if len(updates) == 0 {
			result = a
			return nil
		}
		res := tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return ErrUsernameTaken
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return tx.First(&result, id).Error
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Services) ListAdmins() ([]model.Admin, error) {
	var list []model.Admin
	err := s.DB.Order("id asc").Find(&list).Error
	return list, err
}

var validAdminRoles = map[string]bool{
	"super":    true,
	"operator": true,
	"auditor":  true,
}

type AdminCreateInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
}

func (s *Services) CreateAdmin(in AdminCreateInput) (*model.Admin, error) {
	in.Username = strings.TrimSpace(in.Username)
	if len(in.Username) < 3 || len(in.Username) > 32 || !isSafeName(in.Username) {
		return nil, fmt.Errorf("%w: 账号需为 3-32 位字母、数字或下划线", ErrInvalidParam)
	}
	if len(in.Password) < 12 {
		return nil, fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
	}
	if in.Role == "" {
		in.Role = "operator"
	}
	if !validAdminRoles[in.Role] {
		return nil, fmt.Errorf("%w: 不支持的角色 %q", ErrInvalidParam, in.Role)
	}

	var n int64
	if err := s.DB.Model(&model.Admin{}).Where("username = ?", in.Username).Count(&n).Error; err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrUsernameTaken
	}

	hashed, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	nickname := strings.TrimSpace(in.Nickname)
	if nickname == "" {
		nickname = in.Username
	}
	a := &model.Admin{
		Username:     in.Username,
		Password:     hashed,
		Nickname:     truncate(nickname, 64),
		Role:         in.Role,
		Status:       "active",
		TokenVersion: 1,
	}
	if err := s.DB.Create(a).Error; err != nil {
		return nil, ErrUsernameTaken
	}
	return a, nil
}

type AdminUpdateInput struct {
	Nickname *string `json:"nickname"`
	Role     *string `json:"role"`
	Status   *string `json:"status"`
}

func (s *Services) UpdateAdmin(id, operatorID uint, in AdminUpdateInput) error {
	target, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}

	updates := map[string]any{}
	if in.Nickname != nil {
		updates["nickname"] = truncate(strings.TrimSpace(*in.Nickname), 64)
	}

	roleChanged := in.Role != nil && *in.Role != target.Role
	statusChanged := in.Status != nil && *in.Status != target.Status

	if in.Role != nil || in.Status != nil {
		if id == operatorID {
			return fmt.Errorf("%w: 不能修改自己的角色或状态", ErrInvalidParam)
		}
		if in.Role != nil {
			if !validAdminRoles[*in.Role] {
				return fmt.Errorf("%w: 不支持的角色 %q", ErrInvalidParam, *in.Role)
			}
			if target.Role == "super" && *in.Role != "super" {
				if err := s.assertNotLastSuperAdmin(id, "降级"); err != nil {
					return err
				}
			}
			updates["role"] = *in.Role
		}
		if in.Status != nil {
			if *in.Status != "active" && *in.Status != "disabled" {
				return fmt.Errorf("%w: 不支持的账号状态", ErrInvalidParam)
			}
			if *in.Status != "active" && target.Role == "super" {
				if err := s.assertNotLastSuperAdmin(id, "禁用"); err != nil {
					return err
				}
			}
			updates["status"] = *in.Status
		}
	}

	if roleChanged || statusChanged {
		updates["token_version"] = gorm.Expr("token_version + 1")
	}

	if len(updates) == 0 {
		return nil
	}
	if err := s.applyAdminUpdate(id, updates); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

func (s *Services) applyAdminUpdate(id uint, updates map[string]any) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	return s.DB.Transaction(func(tx *gorm.DB) error {
		var fresh model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fresh, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if err := assertSuperAdminRemainsAfterUpdate(tx, &fresh, updates); err != nil {
			return err
		}
		return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error
	})
}

func assertSuperAdminRemainsAfterUpdate(tx *gorm.DB, target *model.Admin, updates map[string]any) error {
	if target.Role != "super" || target.Status != "active" {
		return nil
	}
	role, status := target.Role, target.Status
	if v, ok := updates["role"].(string); ok {
		role = v
	}
	if v, ok := updates["status"].(string); ok {
		status = v
	}
	if role == "super" && status == "active" {
		return nil
	}
	return assertNotLastSuperAdminIn(tx, target.ID, "降级或禁用")
}

func (s *Services) DeleteAdmin(id, operatorID uint) error {
	if id == operatorID {
		return fmt.Errorf("%w: 不能删除当前登录的账号", ErrInvalidParam)
	}
	target, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if target.Role == "super" {
		if err := s.assertNotLastSuperAdmin(id, "删除"); err != nil {
			return err
		}
	}

	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		var fresh model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fresh, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if fresh.Role == "super" {
			if err := assertNotLastSuperAdminIn(tx, fresh.ID, "删除"); err != nil {
				return err
			}
		}
		return tx.Delete(&model.Admin{}, fresh.ID).Error
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

func (s *Services) AdminSetPassword(id uint, newPassword string) error {
	if len(newPassword) < 12 {
		return fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
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
		return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error
	})
	if err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

func (s *Services) assertNotLastSuperAdmin(excludeID uint, action string) error {
	return assertNotLastSuperAdminIn(s.DB, excludeID, action)
}

func assertNotLastSuperAdminIn(db *gorm.DB, excludeID uint, action string) error {
	var n int64
	if err := db.Model(&model.Admin{}).
		Where("role = ? AND status = ? AND id <> ?", "super", "active", excludeID).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: 系统必须保留至少一个启用的超级管理员，无法%s该账号", ErrInvalidParam, action)
	}
	return nil
}
