package service

import (
	"log"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) ClaimTOTPStep(adminID uint, step int64) bool {
	return s.ClaimTOTPStepTx(s.DB, adminID, step)
}

func (s *Services) ClaimTOTPStepTx(tx *gorm.DB, adminID uint, step int64) bool {
	res := tx.Model(&model.Admin{}).
		Where("id = ? AND totp_last_step < ?", adminID, step).
		Update("totp_last_step", step)
	if res.Error != nil {
		log.Printf("[totp] 更新防重放步进失败（管理员 %d）: %v", adminID, res.Error)
		return false
	}
	return res.RowsAffected == 1
}
