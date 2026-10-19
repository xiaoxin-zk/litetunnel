package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) ListUsers(keyword, status string, groupID uint, offset, limit int) ([]model.User, int64, error) {
	q := s.DB.Model(&model.User{})
	if keyword != "" {
		kw := "%" + keyword + "%"
		q = q.Where("username LIKE ? OR email LIKE ? OR remark LIKE ?", kw, kw, kw)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if groupID > 0 {
		q = q.Where("group_id = ?", groupID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.User
	err := q.Preload("Group").Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

type AdminCreateUserInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	GroupID  uint   `json:"group_id"`
	Remark   string `json:"remark"`
}

func (s *Services) AdminCreateUser(in AdminCreateUserInput) (*model.User, error) {
	username, email, err := validateNewUser(in.Username, in.Email, in.Password)
	if err != nil {
		return nil, err
	}
	if err := s.checkUserUnique(username, email); err != nil {
		return nil, err
	}
	user, err := s.prepareNewUser(username, email, in.Password, "", false)
	if err != nil {
		return nil, err
	}

	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.insertUserTx(tx, user); err != nil {
			return err
		}
		updates := map[string]any{"remark": truncate(in.Remark, 200)}
		if in.GroupID > 0 {
			var g model.Group
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&g, in.GroupID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
				}
				return err
			}
			updates["group_id"] = g.ID
		}
		res := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates)
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
	return s.LoadUser(user.ID)
}

type AdminUpdateUserInput struct {
	Email    *string `json:"email"`
	Nickname *string `json:"nickname"`
	Remark   *string `json:"remark"`
}

func (s *Services) AdminUpdateUser(id uint, in AdminUpdateUserInput) error {
	fields := map[string]any{}
	var email *string
	if in.Email != nil {
		e := strings.ToLower(strings.TrimSpace(*in.Email))
		if e != "" && !IsValidEmail(e) {
			return fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		email = &e
	}
	if in.Nickname != nil {
		fields["nickname"] = truncate(*in.Nickname, 64)
	}
	if in.Remark != nil {
		fields["remark"] = truncate(*in.Remark, 200)
	}
	if len(fields) == 0 && email == nil {
		return ErrInvalidParam
	}
	_, err := s.updateProfileLocked(id, profilePatch{
		email:            email,
		bumpTokenVersion: true,
		fields:           fields,
	})
	return err
}

type userStatusEntry struct {
	gen uint64
	at  time.Time
}

const (
	statusGenMaxEntries = 100000
	statusGenTTL        = 7 * 24 * time.Hour
)

func (s *Services) bumpUserStatusGen(userID uint) uint64 {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	e := s.statusGens[userID]
	e.gen++
	e.at = time.Now()
	s.statusGens[userID] = e
	if len(s.statusGens) > statusGenMaxEntries {
		s.sweepStatusGensLocked(e.at)
	}
	return e.gen
}

func (s *Services) setUserStatusGen(userID uint, gen uint64) {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	s.statusGens[userID] = userStatusEntry{gen: gen, at: time.Now()}
	if len(s.statusGens) > statusGenMaxEntries {
		s.sweepStatusGensLocked(time.Now())
	}
}

func (s *Services) userStateVersionFromDB(userID uint) (uint64, error) {
	gen, _, err := s.userStateVersionAndIncarnation(userID)
	return gen, err
}

func (s *Services) userStateVersionAndIncarnation(userID uint) (uint64, string, error) {
	var u model.User
	if err := s.DB.Select("id", "state_version", "incarnation").
		First(&u, userID).Error; err != nil {
		return 0, "", err
	}
	return u.StateVersion, u.Incarnation, nil
}

func (s *Services) userStatusGen(userID uint) uint64 {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	return s.statusGens[userID].gen
}

func (s *Services) forgetUserStatusGen(userID uint) {
	s.statusGenMu.Lock()
	delete(s.statusGens, userID)
	s.statusGenMu.Unlock()
}

func (s *Services) sweepStatusGensLocked(now time.Time) {
	cutoff := now.Add(-statusGenTTL)
	for id, e := range s.statusGens {
		if e.at.Before(cutoff) {
			delete(s.statusGens, id)
		}
	}
	if len(s.statusGens) <= statusGenMaxEntries {
		return
	}
	target := statusGenMaxEntries / 2
	for id := range s.statusGens {
		if len(s.statusGens) <= target {
			break
		}
		delete(s.statusGens, id)
	}
}

func (s *Services) AdminSetUserStatus(id uint, status string) error {
	switch status {
	case model.UserStatusActive, model.UserStatusDisabled, model.UserStatusBanned:
	default:
		return fmt.Errorf("%w: 不支持的用户状态", ErrInvalidParam)
	}
	lock := s.userLock(id)
	lock.Lock()

	var gen uint64
	var drainIntent string
	var drainNotAfter time.Time
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.User{}).Where("id = ?", id).
			Updates(map[string]any{
				"status":        status,
				"state_version": gorm.Expr("state_version + 1"),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if status != model.UserStatusActive {
			if err := revokeClientSessionsTx(tx, id); err != nil {
				return err
			}
		}
		var u model.User
		if err := tx.Select("state_version", "incarnation").First(&u, id).Error; err != nil {
			return err
		}
		gen = u.StateVersion
		if status != model.UserStatusActive {
			drainNotAfter = time.Now()
			drainIntent = s.recordProxyDrainPendingDB(tx, proxyDrainRequest{
				userID:      id,
				prefix:      FrpUserOf(id) + ".",
				gen:         gen,
				notAfter:    drainNotAfter,
				incarnation: u.Incarnation,
			})
			if drainIntent == "" {
				return errors.New("记录账号禁用断流意图失败")
			}
		}
		return nil
	})
	if err != nil {
		lock.Unlock()
		return err
	}
	s.setUserStatusGen(id, gen)
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	if status != model.UserStatusActive {
		disabledAt := drainNotAfter
		if disabledAt.IsZero() {
			disabledAt = time.Now()
		}
		s.Runtime.BumpGuardVer()
		s.Runtime.SetUserBlocked(id, true)
		s.Runtime.DropUserSessions(id)
		lock.Unlock()

		closeCtx, cancel := context.WithTimeout(context.Background(), closeProxiesTimeout)
		s.closeUserProxiesWithIntent(closeCtx, id, gen, disabledAt, drainIntent)
		cancel()
		return nil
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetUserBlocked(id, false)

	if err := s.refreshQuotaFor(id); err != nil {
		lock.Unlock()
		return fmt.Errorf("账号已启用，但配额标记刷新失败（沿用原有超额状态，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	lock.Unlock()
	return nil
}

func (s *Services) AdminResetUserPassword(id uint, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&locked, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		res := tx.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if err := revokeClientSessionsTx(tx, id); err != nil {
			return err
		}
		return revokePasswordResetTx(tx, id, locked.Email)
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	s.Runtime.DropUserSessions(id)
	return nil
}

func (s *Services) AdminResetUserSecret(id uint) (string, error) {
	u, err := s.LoadUser(id)
	if err != nil {
		return "", err
	}
	return s.ResetClientSecret(u)
}
