package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	emailCodeTTL            = 10 * time.Minute
	emailCodeMaxAttempts    = 5
	emailCodeResendCooldown = 60 * time.Second
	emailCodeDailyPerEmail  = 10
)

const (
	EmailSceneRegister = "register"
	EmailSceneReset    = "reset"
	EmailSceneChange   = "change"
)

func (s *Services) SendEmailCode(email, scene, ip string) error {
	if scene != EmailSceneReset {
		return s.sendEmailCode(email, scene, ip)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !IsValidEmail(email) {
		return ErrEmailRequired
	}
	if !s.MailEnabled() {
		return ErrMailDisabled
	}
	return s.enqueueRecovery(recoveryRequest{account: email, ip: truncate(ip, 64), emailCode: true})
}

func (s *Services) sendEmailCode(email, scene, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !IsValidEmail(email) {
		return ErrEmailRequired
	}
	switch scene {
	case EmailSceneRegister, EmailSceneReset, EmailSceneChange:
	default:
		return ErrInvalidParam
	}
	if !s.MailEnabled() {
		return ErrMailDisabled
	}

	if scene == EmailSceneRegister || scene == EmailSceneChange {
		if v := s.emailDomainVerdictFor(email); v.Reject != nil {
			return v.Reject
		}
	}

	userQuery := s.DB.Model(&model.User{}).Where("lower(email) = ?", email)
	if scene == EmailSceneReset {
		userQuery = userQuery.Where("email_verified = ? AND status = ?", true, model.UserStatusActive)
	}
	var exists int64
	if err := userQuery.Count(&exists).Error; err != nil {
		return err
	}

	if (scene == EmailSceneRegister || scene == EmailSceneChange) && exists > 0 {
		return ErrEmailTaken
	}

	kind := model.MailKindEmailCodeRegister
	switch scene {
	case EmailSceneReset:
		kind = model.MailKindEmailCodeReset
	case EmailSceneChange:
		kind = model.MailKindEmailCodeChange
	}

	if scene == EmailSceneReset && exists == 0 {
		log.Printf("[emailcode] 找回密码请求的邮箱未注册，已静默忽略")
		return nil
	}

	var resetVersion *int
	if scene == EmailSceneReset {
		var u model.User
		if err := s.DB.Model(&model.User{}).
			Select("id", "token_version").
			Where("lower(email) = ? AND email_verified = ?", strings.ToLower(email), true).
			First(&u).Error; err != nil {
			s.recordRecoveryFailure()
			log.Printf("[emailcode] 读取找回验证码的账号版本失败，本次不发送（对外仍返回成功）: %v", err)
			return nil
		}
		v := u.TokenVersion
		resetVersion = &v
	}

	code, err := newNumericCode(6)
	if err != nil {
		if scene == EmailSceneReset {
			s.recordRecoveryFailure()
			log.Printf("[emailcode] 生成找回验证码失败，本次不发送（对外仍返回成功）: %v", err)
			return nil
		}
		return err
	}
	sum := sha256.Sum256([]byte(code))

	siteName := s.Settings.Get(KeySiteName)
	if siteName == "" {
		siteName = "LiteTunnel"
	}
	subject := fmt.Sprintf("【%s】邮箱验证码", siteName)

	_, err = s.enqueueMail(email, subject,
		emailCodeMailBody(siteName, code, int(emailCodeTTL.Minutes())),
		kind, emailCodePayload{
			Email:        email,
			Scene:        scene,
			CodeHash:     hex.EncodeToString(sum[:]),
			TTLSeconds:   int(emailCodeTTL.Seconds()),
			IP:           truncate(ip, 64),
			TokenVersion: resetVersion,
		}, mailQuota{
			cooldown:      emailCodeResendCooldown,
			dailyLimit:    emailCodeDailyPerEmail,
			dailyAllKinds: true,
		})
	if err != nil {
		if scene == EmailSceneReset {
			if !errors.Is(err, errMailQuotaCooldown) && !errors.Is(err, errMailQuotaDaily) {
				s.recordRecoveryFailure()
			}
			log.Printf("[emailcode] 找回密码的验证码未发出（邮箱 %s）: %v", maskEmail(email), err)
			return nil
		}
		switch {
		case errors.Is(err, errMailQuotaCooldown):
			return ErrEmailCodeTooSoon
		case errors.Is(err, errMailQuotaDaily):
			return ErrEmailCodeTooMany
		default:
			return err
		}
	}
	return nil
}

func (s *Services) voidMail(id uint, reason string) {
	if err := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status IN ?", id,
			[]string{model.MailPending, model.MailSending, model.MailActivating}).
		Updates(map[string]any{
			"status":      model.MailFailed,
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    truncate(reason, 255),
		}).Error; err != nil {
		log.Printf("[mail] 作废超额邮件失败（id=%d）: %v", id, err)
	}
}

func (s *Services) VerifyEmailCode(email, scene, code string) error {
	rec, err := s.checkEmailCode(s.DB, email, scene, code)
	if err != nil {
		return err
	}
	return s.consumeEmailCode(s.DB, rec.ID)
}

func (s *Services) checkEmailCode(db *gorm.DB, email, scene, code string) (*model.EmailCode, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return nil, ErrEmailCodeWrong
	}

	var rec model.EmailCode
	err := db.Where("email = ? AND scene = ? AND used_at IS NULL", email, scene).
		Order("id desc").First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrEmailCodeWrong
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(rec.ExpireAt) {
		return nil, ErrEmailCodeWrong
	}
	if rec.Attempts >= emailCodeMaxAttempts {
		return nil, ErrEmailCodeAttempts
	}

	sum := sha256.Sum256([]byte(code))
	ok := subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(sum[:])), []byte(rec.CodeHash)) == 1
	if !ok {
		res := s.DB.Model(&model.EmailCode{}).
			Where("id = ? AND attempts < ?", rec.ID, emailCodeMaxAttempts).
			Update("attempts", gorm.Expr("attempts + 1"))
		if res.Error != nil {
			log.Printf("[emailcode] 记录失败次数出错，拒绝继续校验: %v", res.Error)
			return nil, ErrEmailCodeCheckFailed
		}
		if res.RowsAffected == 0 {
			return nil, ErrEmailCodeAttempts
		}
		return nil, ErrEmailCodeWrong
	}
	return &rec, nil
}

func (s *Services) consumeEmailCode(db *gorm.DB, id uint) error {
	res := db.Model(&model.EmailCode{}).
		Where("id = ? AND used_at IS NULL AND expire_at > ? AND attempts < ?",
			id, time.Now(), emailCodeMaxAttempts).
		Update("used_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrEmailCodeWrong
	}
	return nil
}

func newNumericCode(n int) (string, error) {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		sb.WriteByte(byte('0' + v.Int64()))
	}
	return sb.String(), nil
}

func emailCodeMailBody(siteName, code string, ttlMinutes int) string {
	return fmt.Sprintf(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#1f2937;">邮箱验证码</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 20px;">
      你正在使用 %s。请在页面中填写下面的验证码：
    </p>
    <p style="margin:0 0 20px;">
      <span style="display:inline-block;background:#f3f4f6;border-radius:10px;
        padding:14px 26px;font-size:30px;letter-spacing:8px;font-weight:600;
        color:#111827;font-family:ui-monospace,Menlo,Consolas,monospace;">%s</span>
    </p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 18px;">
      验证码 %d 分钟内有效，且只能使用一次。
    </p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      如果这不是你本人的操作，请忽略本邮件。<br>
      请勿把验证码告诉任何人，包括自称客服的人。
    </p>
  </div>
</body></html>`, siteName, code, ttlMinutes)
}
