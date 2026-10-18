package service

import (
	"strings"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// purgeEmailCredentialsTx 作废与某个邮箱地址绑定的恢复凭据。
//
// 包括三样：
//
//   - 该账号的重置令牌（令牌按 user_id 生效，**不核对邮箱**，
//     所以换掉邮箱之后旧链接照样能改密码）；
//   - 发往该地址的验证码记录；
//   - 已排队或已送达但尚未激活的邮件。
//
// 换绑邮箱时必须调用；「未启用邮件时直接改邮箱」也必须调用——
// 邮件开关随时可能被重新打开，这些历史遗留到那时就是一条后门。
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
			"status": model.MailFailed,
			// 清空领取令牌：正在发送/激活的实例随后回写时会被条件挡住，
			// 不会把作废的记录改回 sent / delivered。
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "邮箱已更换，邮件作废",
		}).Error
}

// purgeAccountCredentialsTx 清理账号关联的凭据与待发邮件（在事务内执行）。
//
// 管理员删除与自助注销共用：留着这些记录，用户会收到指向不存在账号的
// 重置邮件——激活阶段虽然也会发现账号不在（见 activateResetToken），
// 但信已经发出去了，用户看到的是「链接无效」而不是「账号已注销」；
// 队列还会为一个不存在的账号反复投递。邮件正文与参数里是明文凭据，
// 作废时立刻清掉。
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
			"status": model.MailFailed,
			// 同上：清空令牌，避免在途的发送/激活把作废记录改回终态。
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "账号已删除，邮件作废",
		}).Error
}

// 说明：改邮箱不再有单独入口。它曾经是一个独立函数（先锁、先提交），
// 与随后写入的昵称/备注分开提交，于是「后一步失败」会留下「接口报失败、
// 邮箱却已经改了」的半成品。现在整组资料变更统一走 user_profile.go 的
// updateProfileLocked：一把用户锁、一个事务、一次提交。
