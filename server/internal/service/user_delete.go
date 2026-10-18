package service

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// DeleteAccount 用户注销自己的账号。
//
// 需要提供登录密码二次确认：注销不可恢复，必须防止令牌被盗后被恶意注销。
// 关联数据一并清理，避免留下悬空记录。
//
// 与 AdminDeleteUser 共用 account_lifecycle.go 里的事务与善后两段，
// 唯一差别是这里多一道密码复核（在事务内、用户行锁内做）。
func (s *Services) DeleteAccount(userID uint, password string) error {
	ports, err := s.deleteAccountTx(userID, password)
	if err != nil {
		return err
	}
	s.purgeAccountAfterCommit(userID, ports)
	return nil
}

// deleteAccountTx 在用户锁内完成注销事务，返回需要回收的端口清单。
//
// 锁的语义与 deleteUserTx 完全一致（只罩住事务、defer 释放），理由不再重复。
func (s *Services) deleteAccountTx(userID uint, password string) ([]portProto, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	var ports []portProto
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		ports, err = accountPurgeTx(tx, userID, func(u *model.User) error {
			// 密码校验放在锁内、事务内：事务外先验一遍的话，并发改密会让
			// 「密码正确」的结论作废——注销必须基于**当前**密码，而不是
			// 请求开始时的旧快照。
			if !auth.VerifyPassword(u.Password, password) {
				return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
			}
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return ports, nil
}
