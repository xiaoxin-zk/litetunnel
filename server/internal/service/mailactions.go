package service

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// emailCodePayload 是「邮箱验证码」类邮件的凭据参数。
//
// 验证码记录**不在这封信进发件箱时就创建**，而是等它真的送达之后才创建：
// 只有这样，投递失败时才不会出现「新码没到、旧码已废」的窘境。
type emailCodePayload struct {
	Email    string    `json:"email"`
	Scene    string    `json:"scene"`
	CodeHash string    `json:"code_hash"`
	ExpireAt time.Time `json:"expire_at"`
	IP       string    `json:"ip"`
}

// resetLinkPayload 是「重置密码链接」类邮件的凭据参数。
type resetLinkPayload struct {
	UserID    uint      `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	ExpireAt  time.Time `json:"expire_at"`
	IP        string    `json:"ip"`
}

// applyMailAction 在邮件**确认送达之后**让新凭据生效，并作废同类的旧凭据。
//
// # 为什么必须等到送达
//
// 以前的顺序是「写队列 → 立即作废旧凭据」。而队列在内存里、发送失败只记一行
// 日志：信没发出去，旧凭据却已经废了，用户手上一个可用的凭据都没有——
// 账号就此找不回来，而且他每点一次「重新发送」都重复这个过程。
//
// 现在顺序反过来：送达到才生效。投递失败只是「这次没收到」，
// 用户原有的凭据仍然可用，可以随时再试。
func (s *Services) applyMailAction(row model.MailOutbox) error {
	switch row.Kind {
	case model.MailKindEmailCodeRegister, model.MailKindEmailCodeReset:
		return s.activateEmailCode(row)
	case model.MailKindResetLink:
		return s.activateResetToken(row)
	default:
		// 未知类型：邮件已经发出去了，但没有凭据要激活。
		// 不报错——报错会把它标成 failed，而实际上信是发出去的。
		return nil
	}
}

// activateEmailCode 创建验证码记录，并作废同一邮箱同一场景下的旧码。
//
// 两步放在同一个事务里：中间失败会留下「旧码已废、新码没建」的状态，
// 与我们要修的问题一模一样。
func (s *Services) activateEmailCode(row model.MailOutbox) error {
	var p emailCodePayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 同一邮箱同一场景只保留最新一个可用验证码：否则用户连点几次后，
		// 前面几封邮件里的码也都还能用，等于扩大了攻击面。
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND used_at IS NULL", p.Email, p.Scene).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.EmailCode{
			Email:    p.Email,
			Scene:    p.Scene,
			CodeHash: p.CodeHash,
			ExpireAt: p.ExpireAt,
			IP:       p.IP,
		}).Error
	})
}

// activateResetToken 创建重置令牌，并作废该账号的旧令牌。
func (s *Services) activateResetToken(row model.MailOutbox) error {
	var p resetLinkPayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 同一账号只保留一个有效令牌：避免多封邮件里的链接同时可用。
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND used_at IS NULL", p.UserID).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.PasswordResetToken{
			UserID:    p.UserID,
			TokenHash: p.TokenHash,
			ExpireAt:  p.ExpireAt,
			IP:        p.IP,
		}).Error
	})
}
