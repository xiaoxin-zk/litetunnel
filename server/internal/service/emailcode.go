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
	// emailCodeTTL 是验证码有效期。过长会放大邮件被转发/截图带来的风险。
	emailCodeTTL = 10 * time.Minute
	// emailCodeMaxAttempts 是单个验证码允许的校验失败次数。
	// 6 位数字有 100 万种可能，5 次上限把暴力枚举的期望成功率压到百万分之五。
	emailCodeMaxAttempts = 5
	// emailCodeResendCooldown 是同一邮箱同一场景的重发间隔。
	emailCodeResendCooldown = 60 * time.Second
	// emailCodeDailyPerEmail 是同一邮箱每日可发送的验证码数量上限。
	emailCodeDailyPerEmail = 10
)

// 验证码场景。
const (
	// EmailSceneRegister 注册邮箱验证：要求邮箱未被占用。
	EmailSceneRegister = "register"
	// EmailSceneReset 找回密码：绝不暴露邮箱是否注册过。
	EmailSceneReset = "reset"
)

// SendEmailCode 发送一次性邮箱验证码。
//
// 三层限流叠加，缺任何一层都会让「拿别人的邮箱反复触发发送」成为骚扰手段：
//  1. 同邮箱重发冷却（60 秒）
//  2. 同邮箱每日上限（10 条）
//  3. 路由层的 IP 令牌桶
func (s *Services) SendEmailCode(email, scene, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !IsValidEmail(email) {
		return ErrEmailRequired
	}
	if scene != EmailSceneRegister && scene != EmailSceneReset {
		return ErrInvalidParam
	}
	if !s.MailEnabled() {
		return ErrMailDisabled
	}

	var exists int64
	if err := s.DB.Model(&model.User{}).Where("email = ?", email).Count(&exists).Error; err != nil {
		return err
	}

	// 注册场景：邮箱已被占用必须明确告知，否则用户无法继续。
	// 找回场景：**绝不能**暴露邮箱是否注册过，否则本接口会退化成账号枚举工具。
	if scene == EmailSceneRegister && exists > 0 {
		return ErrEmailTaken
	}

	kind := model.MailKindEmailCodeRegister
	if scene == EmailSceneReset {
		kind = model.MailKindEmailCodeReset
	}

	// 限流 1：同邮箱同用途的重发冷却。
	//
	// 计数改为看**发件箱**而不是验证码表：验证码记录现在要等送达才创建，
	// 拿它做限流的话，反复触发发送就能绕过冷却（每次都还没送达）。
	// 用发件箱计数也更贴合限流的本意——拦的是「发送行为」，不是「可用验证码」。
	var recent model.MailOutbox
	err := s.DB.Where("to_addr = ? AND kind = ?", email, kind).
		Order("id desc").First(&recent).Error
	if err == nil && time.Since(recent.CreatedAt) < emailCodeResendCooldown {
		return ErrEmailCodeTooSoon
	}

	// 限流 2：同邮箱每日上限（不限用途，与原先按邮箱统计一致）。
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var sent int64
	if err := s.DB.Model(&model.MailOutbox{}).
		Where("to_addr = ? AND created_at >= ?", email, dayStart).
		Count(&sent).Error; err != nil {
		return err
	}
	if sent >= emailCodeDailyPerEmail {
		return ErrEmailCodeTooMany
	}

	// 找回场景且邮箱不存在：不真的发信，但仍返回成功。
	// 走完了上面全部限流逻辑，因此响应时间与「邮箱存在」时基本一致。
	if scene == EmailSceneReset && exists == 0 {
		log.Printf("[emailcode] 找回密码请求的邮箱未注册，已静默忽略")
		return nil
	}

	code, err := newNumericCode(6)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(code))

	siteName := s.Settings.Get(KeySiteName)
	if siteName == "" {
		siteName = "LiteTunnel"
	}
	subject := fmt.Sprintf("【%s】邮箱验证码", siteName)

	// 只写发件箱，**不建验证码记录**：记录等这封信真的送达之后再创建
	// （见 applyMailAction）。这样投递失败时用户手上的旧码依然可用，
	// 而不是「新码没到、旧码已废」。
	//
	// 投递走异步队列：SMTP 往返可能耗时数秒，
	// 同步发送会让「邮箱是否存在」通过响应时间泄露出去。
	if err := s.queueMail(email, subject,
		emailCodeMailBody(siteName, code, int(emailCodeTTL.Minutes())),
		kind, emailCodePayload{
			Email:    email,
			Scene:    scene,
			CodeHash: hex.EncodeToString(sum[:]),
			// 存 TTL 而不是绝对时间：有效期从**送达时刻**起算。
			// 存绝对时间的话，发件箱重试（1/2/4/8 分钟）加上积压，很容易让
			// 用户收到一个已经过期的码——邮件正文写着「10 分钟内有效」，
			// 实际上一到手就失效了。
			TTLSeconds: int(emailCodeTTL.Seconds()),
			IP:         truncate(ip, 64),
		}); err != nil {
		// 找回场景必须保持「不暴露账号是否存在」：这里已经走完了账号判断，
		// 返回错误会让「已注册 + 入队失败」与「未注册」变得可区分。
		if scene == EmailSceneReset {
			log.Printf("[emailcode] 找回密码的验证码入队失败（邮箱 %s）: %v", maskEmail(email), err)
			return nil
		}
		// 注册场景可以直接告知失败：邮箱是用户自己填的，不存在枚举问题。
		return err
	}
	return nil
}

// VerifyEmailCode 校验并消费邮箱验证码。
//
// 一次性：校验通过即标记 used_at。失败累计到上限则整条作废，
// 防止 6 位码被暴力枚举。
func (s *Services) VerifyEmailCode(email, scene, code string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return ErrEmailCodeWrong
	}

	var rec model.EmailCode
	err := s.DB.Where("email = ? AND scene = ? AND used_at IS NULL", email, scene).
		Order("id desc").First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrEmailCodeWrong
	}
	if err != nil {
		return err
	}
	if time.Now().After(rec.ExpireAt) {
		return ErrEmailCodeWrong
	}
	if rec.Attempts >= emailCodeMaxAttempts {
		return ErrEmailCodeAttempts
	}

	sum := sha256.Sum256([]byte(code))
	ok := subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(sum[:])), []byte(rec.CodeHash)) == 1
	if !ok {
		// 失败计数用数据库侧自增，避免并发下绕过次数上限。
		if err := s.DB.Model(&model.EmailCode{}).Where("id = ?", rec.ID).
			Update("attempts", gorm.Expr("attempts + 1")).Error; err != nil {
			log.Printf("[emailcode] 更新失败次数出错: %v", err)
		}
		return ErrEmailCodeWrong
	}

	// 条件更新消费：并发下只有一个请求能把 used_at 从 NULL 改成功。
	res := s.DB.Model(&model.EmailCode{}).
		Where("id = ? AND used_at IS NULL", rec.ID).
		Update("used_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrEmailCodeWrong
	}
	return nil
}

// newNumericCode 生成指定长度的数字验证码。
//
// 用 crypto/rand 而不是 math/rand：后者可预测，攻击者观察到几个码就能推出后续值。
// 逐位取随机数而不是对单字节取模，是为了避免取模偏置（256 不是 10 的整数倍，
// 直接 %10 会让 0-5 比 6-9 更容易出现）。
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

// emailCodeMailBody 生成验证码邮件正文。
//
// 刻意采用内联样式的简单 HTML：邮件客户端对外部样式表支持极差。
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
