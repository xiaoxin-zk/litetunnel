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
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	resetTokenTTL   = 30 * time.Minute
	resetTokenBytes = 32
)

var ErrMailDisabled = errors.New("站点未配置邮件服务，请联系管理员重置密码")

var ErrMailQueueFull = errors.New("邮件发送队列繁忙，请稍后重试")

var ErrFirewallUnavailable = errors.New("宿主机防火墙 helper 不可用")

var (
	ErrResetTokenInvalid = errors.New("重置链接无效，请重新申请")
	ErrResetTokenExpired = errors.New("重置链接已过期，请重新申请")
)

func (s *Services) RequestPasswordReset(account, ip, baseURL string) error {
	if !s.MailEnabled() {
		return ErrMailDisabled
	}
	return s.enqueueRecovery(recoveryRequest{account: strings.TrimSpace(account), ip: truncate(ip, 64), baseURL: baseURL})
}

func (s *Services) requestPasswordReset(account, ip, baseURL string) error {
	if !s.MailEnabled() {
		return ErrMailDisabled
	}

	account = strings.TrimSpace(account)
	if account == "" {
		return nil
	}

	if strings.TrimSpace(baseURL) == "" {
		s.recordRecoveryFailure()
		log.Printf("[reset] 缺少对外地址，无法生成重置链接，本次不发信")
		return nil
	}

	u, err := s.findUserByAccount(account)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.recordRecoveryFailure()
	}
	if err != nil || u.Email == "" || !u.EmailVerified || u.Status != model.UserStatusActive {
		log.Printf("[reset] 找回密码请求未命中有效账号（输入长度 %d）", len(account))
		return nil
	}

	plain, hash, err := newResetToken()
	if err != nil {
		s.recordRecoveryFailure()
		log.Printf("[reset] 生成令牌失败: %v", err)
		return nil
	}

	siteName := s.Settings.Get(KeySiteName)
	if siteName == "" {
		siteName = "LiteTunnel"
	}
	link := strings.TrimRight(baseURL, "/") + "/reset-password?token=" + plain
	subject := fmt.Sprintf("【%s】重置登录密码", siteName)
	body := resetMailBody(siteName, u.Username, link, int(resetTokenTTL.Minutes()))

	tokenVersion := u.TokenVersion
	if _, err := s.enqueueMail(u.Email, subject, body, model.MailKindResetLink, resetLinkPayload{
		UserID:       u.ID,
		TokenHash:    hash,
		TTLSeconds:   int(resetTokenTTL.Seconds()),
		IP:           truncate(ip, 64),
		TokenVersion: &tokenVersion,
	}, mailQuota{cooldown: resetLinkCooldown, dailyLimit: resetLinkDailyPerEmail}); err != nil {
		if !errors.Is(err, errMailQuotaCooldown) && !errors.Is(err, errMailQuotaDaily) {
			s.recordRecoveryFailure()
		}
		log.Printf("[reset] 重置邮件未发出（账号 %d），原有令牌未受影响: %v", u.ID, err)
		return nil
	}
	return nil
}

const (
	resetLinkCooldown      = 60 * time.Second
	resetLinkDailyPerEmail = 5
)

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
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, tok.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrResetTokenInvalid
			}
			return err
		}

		res := tx.Model(&model.PasswordResetToken{}).
			Where("id = ? AND used_at IS NULL AND expire_at > ?", tok.ID, now).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrResetTokenInvalid
		}

		res = tx.Model(&model.User{}).Where("id = ?", tok.UserID).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
			"client_secret": newSecret,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrResetTokenInvalid
		}

		if err := tx.Model(&model.ClientSession{}).
			Where("user_id = ?", tok.UserID).
			Update("online", false).Error; err != nil {
			return err
		}

		return revokePasswordResetTx(tx, tok.UserID, u.Email)
	})
	if err != nil {
		return err
	}

	s.finishPasswordReset(tok.UserID, ip)
	log.Printf("[reset] 用户 %d 已通过邮件重置密码（来源 %s）", tok.UserID, ip)
	return nil
}

func (s *Services) ResetPasswordByOldPassword(account, oldPassword, newPassword, ip string) error {
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	u, err := s.findUserByAccount(account)
	if err != nil {
		return ErrBadCredentials
	}
	if u.Status != model.UserStatusActive {
		return ErrAccountDisabled
	}

	hashed, newSecret, err := s.preparePasswordReset(newPassword)
	if err != nil {
		return err
	}

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&locked, u.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBadCredentials
			}
			return err
		}
		if locked.Status != model.UserStatusActive {
			return ErrAccountDisabled
		}
		if !auth.VerifyPassword(locked.Password, oldPassword) {
			return ErrBadCredentials
		}
		if auth.VerifyPassword(locked.Password, newPassword) {
			return fmt.Errorf("%w: 新密码不能与当前密码相同", ErrInvalidParam)
		}
		return s.applyPasswordResetTx(tx, u.ID, hashed, newSecret)
	})
	if err != nil {
		return err
	}

	s.finishPasswordReset(u.ID, ip)
	return nil
}

func (s *Services) ResetPasswordByEmailCode(account, emailCode, newPassword, ip string) error {
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	u, err := s.findUserByAccount(account)
	if err != nil {
		return ErrEmailCodeWrong
	}
	if u.Status != model.UserStatusActive {
		return ErrAccountDisabled
	}
	if u.Email == "" {
		return fmt.Errorf("%w: 该账号未绑定邮箱，无法通过邮箱重置，请联系管理员", ErrInvalidParam)
	}
	if !u.EmailVerified {
		return ErrEmailCodeWrong
	}
	rec, err := s.checkEmailCode(s.DB, u.Email, EmailSceneReset, emailCode)
	if err != nil {
		return err
	}

	hashed, newSecret, err := s.preparePasswordReset(newPassword)
	if err != nil {
		return err
	}

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.consumeEmailCode(tx, rec.ID); err != nil {
			return err
		}
		return s.applyPasswordResetTx(tx, u.ID, hashed, newSecret)
	})
	if err != nil {
		return err
	}

	s.finishPasswordReset(u.ID, ip)
	return nil
}

func validateNewPassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	if len(p) > 128 {
		return fmt.Errorf("%w: 密码长度不得超过 128 位", ErrInvalidParam)
	}
	return nil
}

func (s *Services) preparePasswordReset(newPassword string) (hashed, newSecret string, err error) {
	hashed, err = auth.HashPassword(newPassword)
	if err != nil {
		return "", "", err
	}
	newSecret, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	return hashed, newSecret, nil
}

func (s *Services) applyPasswordResetTx(tx *gorm.DB, userID uint, hashed, newSecret string) error {
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrResetTokenInvalid
		}
		return err
	}

	res := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
		"client_secret": newSecret,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrResetTokenInvalid
	}
	if err := revokeClientSessionsTx(tx, userID); err != nil {
		return err
	}
	return revokePasswordResetTx(tx, userID, u.Email)
}

func revokePasswordResetTx(tx *gorm.DB, userID uint, email string) error {
	now := time.Now()
	if err := tx.Model(&model.PasswordResetToken{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Update("used_at", now).Error; err != nil {
		return err
	}
	if email == "" {
		return nil
	}
	lower := strings.ToLower(email)

	if err := tx.Model(&model.EmailCode{}).
		Where("lower(email) = ? AND scene = ? AND used_at IS NULL", lower, EmailSceneReset).
		Update("used_at", now).Error; err != nil {
		return err
	}

	return tx.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind IN ? AND status IN ?",
			lower,
			[]string{model.MailKindResetLink, model.MailKindEmailCodeReset},
			[]string{model.MailPending, model.MailSending, model.MailActivating, model.MailDelivered}).
		Updates(map[string]any{
			"status":      model.MailFailed,
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "密码已修改，重置凭据作废",
		}).Error
}

func (s *Services) finishPasswordReset(userID uint, ip string) {
	s.Runtime.DropUserSessions(userID)

	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	log.Printf("[reset] 用户 %d 已重置密码（来源 %s）", userID, ip)
}

func (s *Services) findUserByAccount(account string) (*model.User, error) {
	var u model.User
	err := s.DB.Where("username = ? OR lower(email) = ?", account, strings.ToLower(account)).
		First(&u).Error
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
