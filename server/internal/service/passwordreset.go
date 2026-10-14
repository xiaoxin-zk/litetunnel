package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	// resetTokenTTL 是重置链接的有效期。过长会放大邮件被转发带来的风险。
	resetTokenTTL = 30 * time.Minute
	// resetTokenBytes 是令牌的随机字节数，256 位熵足以抵抗暴力猜测。
	resetTokenBytes = 32
)

// ErrMailDisabled 表示站点未配置邮件服务。
// 这是配置问题，与账号是否存在无关，因此可以安全地对外暴露。
var ErrMailDisabled = errors.New("站点未配置邮件服务，请联系管理员重置密码")

// 重置令牌相关错误。
var (
	ErrResetTokenInvalid = errors.New("重置链接无效，请重新申请")
	ErrResetTokenExpired = errors.New("重置链接已过期，请重新申请")
)

// MailEnabled 返回是否可通过邮件找回密码。
func (s *Services) MailEnabled() bool { return s.Mail.Enabled() }

// RequestPasswordReset 发起找回密码。account 可以是用户名或邮箱。
//
// 安全要求：无论账号是否存在、是否填写邮箱、是否被禁用，
// 本方法都返回 nil 且耗时基本一致——否则该接口会退化成账号枚举工具。
// 真正的失败原因只写日志。
func (s *Services) RequestPasswordReset(account, ip, baseURL string) error {
	if !s.Mail.Enabled() {
		return ErrMailDisabled
	}

	account = strings.TrimSpace(account)
	if account == "" {
		return nil
	}

	u, err := s.findUserByAccount(account)
	if err != nil || u.Email == "" || u.Status != model.UserStatusActive {
		// 静默返回，不区分具体原因。
		log.Printf("[reset] 找回密码请求未命中有效账号（输入长度 %d）", len(account))
		return nil
	}

	plain, hash, err := newResetToken()
	if err != nil {
		log.Printf("[reset] 生成令牌失败: %v", err)
		return nil
	}

	// 同一账号只保留一个有效令牌：作废旧令牌，避免多封邮件同时可用。
	if err := s.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ? AND used_at IS NULL", u.ID).
		Update("used_at", time.Now()).Error; err != nil {
		log.Printf("[reset] 作废旧令牌失败: %v", err)
		return nil
	}

	tok := model.PasswordResetToken{
		UserID:    u.ID,
		TokenHash: hash,
		ExpireAt:  time.Now().Add(resetTokenTTL),
		IP:        truncate(ip, 64),
	}
	if err := s.DB.Create(&tok).Error; err != nil {
		log.Printf("[reset] 保存令牌失败: %v", err)
		return nil
	}

	link := strings.TrimRight(baseURL, "/") + "/reset-password?token=" + plain
	subject := fmt.Sprintf("【%s】重置登录密码", s.Cfg.SMTP.SiteName)
	body := resetMailBody(s.Cfg.SMTP.SiteName, u.Username, link, int(resetTokenTTL.Minutes()))

	// 投递走异步队列：SMTP 往返可能耗时数秒，
	// 若同步发送会让「账号存在」的响应明显变慢，从而泄露账号是否存在。
	s.enqueueMail(u.Email, subject, body)
	return nil
}

// ResetPassword 使用令牌重置密码。
//
// 成功后自增 TokenVersion 并吊销客户端接入凭据：
// 重置密码通常意味着账号可能已被他人控制，必须把攻击者踢下线。
func (s *Services) ResetPassword(token, newPassword, ip string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrResetTokenInvalid
	}
	if len(newPassword) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}

	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var tok model.PasswordResetToken
	err := s.DB.Where("token_hash = ?", hash).First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrResetTokenInvalid
	}
	if err != nil {
		return err
	}
	if tok.UsedAt != nil {
		return ErrResetTokenInvalid
	}
	if time.Now().After(tok.ExpireAt) {
		return ErrResetTokenExpired
	}

	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	newSecret, err := randomHex(32)
	if err != nil {
		return err
	}

	now := time.Now()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// 条件更新：并发下只有一个请求能把 used_at 从 NULL 改成功，
		// 从而保证令牌只能被使用一次。
		res := tx.Model(&model.PasswordResetToken{}).
			Where("id = ? AND used_at IS NULL", tok.ID).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrResetTokenInvalid
		}

		if err := tx.Model(&model.User{}).Where("id = ?", tok.UserID).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
			// 客户端凭据一并吊销，避免已泄露的 frpc 配置继续可用。
			"client_secret": newSecret,
		}).Error; err != nil {
			return err
		}

		// 该用户已建立的客户端会话全部标记离线，迫使其重新认证。
		return tx.Model(&model.ClientSession{}).
			Where("user_id = ?", tok.UserID).
			Update("online", false).Error
	})
	if err != nil {
		return err
	}

	s.Runtime.InvalidateIdentity(IdentityKindUser, tok.UserID)
	log.Printf("[reset] 用户 %d 已通过邮件重置密码（来源 %s）", tok.UserID, ip)
	return nil
}

// findUserByAccount 支持用用户名或邮箱定位账号。
func (s *Services) findUserByAccount(account string) (*model.User, error) {
	var u model.User
	err := s.DB.Where("username = ? OR email = ?", account, strings.ToLower(account)).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func newResetToken() (plain, hash string, err error) {
	buf := make([]byte, resetTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	plain = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(sum[:]), nil
}

// resetMailBody 生成重置邮件正文。
//
// 刻意采用内联样式的简单 HTML：邮件客户端对外部样式表支持极差。
func resetMailBody(siteName, username, link string, ttlMinutes int) string {
	return fmt.Sprintf(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#1f2937;">重置登录密码</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 18px;">
      你好 %s，我们收到了 %s 的密码重置请求。<br>
      点击下面的按钮设置新密码，链接 %d 分钟内有效。
    </p>
    <p style="margin:0 0 22px;">
      <a href="%s" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
         padding:11px 22px;border-radius:9px;font-weight:500;">设置新密码</a>
    </p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 14px;">
      按钮无法点击时，请复制下面的链接到浏览器打开：
    </p>
    <p style="word-break:break-all;color:#2563eb;font-size:13px;margin:0 0 18px;">%s</p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      如果这不是你本人的操作，请忽略本邮件，你的密码不会发生变化。<br>
      为保障账号安全，重置成功后所有已登录设备都将下线。
    </p>
  </div>
</body></html>`, username, siteName, ttlMinutes, link, link)
}
