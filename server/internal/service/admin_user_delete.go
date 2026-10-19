package service

import (
	"gorm.io/gorm"
)

func (s *Services) AdminDeleteUser(id uint) error {
	intents, err := s.deleteUserTx(id)
	if err != nil {
		return err
	}
	s.purgeAccountAfterCommit(id, intents)
	return nil
}

func (s *Services) deleteUserTx(id uint) ([]portIntent, error) {
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		intents, err = accountPurgeTx(tx, id, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	return intents, nil
}
