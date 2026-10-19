package service

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) DeleteAccount(userID uint, password string) error {
	intents, err := s.deleteAccountTx(userID, password)
	if err != nil {
		return err
	}
	s.purgeAccountAfterCommit(userID, intents)
	return nil
}

func (s *Services) deleteAccountTx(userID uint, password string) ([]portIntent, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		intents, err = accountPurgeTx(tx, userID, func(u *model.User) error {
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
	return intents, nil
}
