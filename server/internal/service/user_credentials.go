package service

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

// changeEmailLocked 在用户行锁内改邮箱：重读当前邮箱、做唯一性校验、写库并
// 作废旧地址的恢复凭据（重置令牌/验证码/待发邮件）。
//
// 邮箱是找回密码的入口，改邮箱与作废旧凭据必须同一个事务；而且判断必须基于
// 行锁后的当前值，不能用调用方事务外读到的旧邮箱——否则会漏清新邮箱的凭据，
// 或覆盖并发换绑刚写入的新地址。
//
// requireVerification：自助改邮箱时若站点开了邮件，必须走「更换邮箱」验证流程；
// 管理员改邮箱不设此约束。incrementTokenVersion：让该用户的既有网页会话失效。
// 返回 changed 表示邮箱是否真的发生了变更。
func (s *Services) changeEmailLocked(userID uint, email string, requireVerification, incrementTokenVersion bool) (bool, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	changed := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var cur model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&cur, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if email == strings.ToLower(strings.TrimSpace(cur.Email)) {
			return nil
		}
		if requireVerification && s.MailEnabled() {
			return fmt.Errorf("%w: 修改邮箱需要验证新地址，请使用「更换邮箱」流程", ErrInvalidParam)
		}
		if email != "" {
			var taken int64
			if err := tx.Model(&model.User{}).
				Where("lower(email) = ? AND id <> ?", email, userID).
				Count(&taken).Error; err != nil {
				return err
			}
			if taken > 0 {
				return ErrEmailTaken
			}
		}
		updates := map[string]any{
			"email":          email,
			"email_verified": false,
		}
		if incrementTokenVersion {
			updates["token_version"] = gorm.Expr("token_version + 1")
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
			return err
		}
		if err := purgeEmailCredentialsTx(tx, userID, cur.Email); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if changed && incrementTokenVersion {
		s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	}
	return changed, nil
}
