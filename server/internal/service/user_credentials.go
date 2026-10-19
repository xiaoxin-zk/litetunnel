package service

import (
	"strings"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func purgeEmailCredentialsTx(tx *gorm.DB, userID uint, email string) error {
	if err := tx.Where("user_id = ?", userID).Delete(&model.PasswordResetToken{}).Error; err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil
	}
	if err := tx.Where("lower(email) = ?", email).Delete(&model.EmailCode{}).Error; err != nil {
		return err
	}
	return tx.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind IN ? AND status IN ?", email,
			[]string{model.MailKindResetLink, model.MailKindEmailCodeReset,
				model.MailKindEmailCodeChange},
			[]string{model.MailPending, model.MailSending, model.MailActivating, model.MailDelivered}).
		Updates(map[string]any{
			"status":      model.MailFailed,
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "邮箱已更换，邮件作废",
		}).Error
}

func purgeAccountCredentialsTx(tx *gorm.DB, userID uint, email string) error {
	if err := tx.Where("user_id = ?", userID).Delete(&model.PasswordResetToken{}).Error; err != nil {
		return err
	}
	if email == "" {
		return nil
	}
	if err := tx.Where("lower(email) = ?", strings.ToLower(email)).
		Delete(&model.EmailCode{}).Error; err != nil {
		return err
	}
	return tx.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind IN ? AND status IN ?", strings.ToLower(email),
			[]string{model.MailKindResetLink, model.MailKindEmailCodeReset,
				model.MailKindEmailCodeRegister, model.MailKindEmailCodeChange},
			[]string{model.MailPending, model.MailSending, model.MailActivating, model.MailDelivered}).
		Updates(map[string]any{
			"status":      model.MailFailed,
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "账号已删除，邮件作废",
		}).Error
}
