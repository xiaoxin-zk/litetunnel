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
	// EmailSceneChange 更换邮箱：验证码发到**新地址**，同样要求未被他人占用。
	//
	// 为什么必须单独一个场景而不是复用 register：两者的限流冷却、
	// 旧码作废范围都按场景划分；混用会让「换个邮箱」和「注册」互相
	// 作废对方的验证码。
	EmailSceneChange = "change"
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
	switch scene {
	case EmailSceneRegister, EmailSceneReset, EmailSceneChange:
	default:
		return ErrInvalidParam
	}
	if !s.MailEnabled() {
		return ErrMailDisabled
	}

	// 找回场景只认「已验证」的邮箱：未验证的地址从来没证明过归属，
	// 不能当作恢复凭据（见 ForgotPassword 的同一条规则）。
	// 用 lower() 比较：老库里可能存着大小写混写的地址。
	userQuery := s.DB.Model(&model.User{}).Where("lower(email) = ?", email)
	if scene == EmailSceneReset {
		userQuery = userQuery.Where("email_verified = ?", true)
	}
	var exists int64
	if err := userQuery.Count(&exists).Error; err != nil {
		return err
	}

	// 注册与换绑场景：邮箱已被占用必须明确告知，否则用户无法继续。
	// 找回场景：**绝不能**暴露邮箱是否注册过，否则本接口会退化成账号枚举工具。
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

	// 找回场景且邮箱不存在：不真的发信，但仍返回成功。
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
	_, err = s.enqueueMail(email, subject,
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
		}, mailQuota{
			cooldown:   emailCodeResendCooldown,
			dailyLimit: emailCodeDailyPerEmail,
			// 与原先一致：同一地址的验证码总数（不分注册/找回/换绑）受限。
			dailyAllKinds: true,
		})
	if err != nil {
		// 找回场景必须保持「不暴露账号是否存在、是否被限流」：这里已经走完了
		// 账号判断，返回错误会让「已注册 + 入队失败」与「未注册」变得可区分。
		if scene == EmailSceneReset {
			log.Printf("[emailcode] 找回密码的验证码未发出（邮箱 %s）: %v", maskEmail(email), err)
			return nil
		}
		switch {
		case errors.Is(err, errMailQuotaCooldown):
			return ErrEmailCodeTooSoon
		case errors.Is(err, errMailQuotaDaily):
			return ErrEmailCodeTooMany
		default:
			// 注册场景可以直接告知失败：邮箱是用户自己填的，不存在枚举问题。
			return err
		}
	}
	return nil
}

// voidMail 作废一封尚未投递的邮件：不再发送，正文与参数一并清掉。
//
// 条件更新（pending / sending）：如果它已经被 worker 取走发出去了，
// 这里不改状态——那封信的凭据动作会由激活环节按当前账号状态再判一次。
func (s *Services) voidMail(id uint, reason string) {
	if err := s.DB.Model(&model.MailOutbox{}).
		Where("id = ? AND status IN ?", id, []string{model.MailPending, model.MailSending}).
		Updates(map[string]any{
			"status":   model.MailFailed,
			"body":     "",
			"payload":  "",
			"last_err": truncate(reason, 255),
		}).Error; err != nil {
		log.Printf("[mail] 作废超额邮件失败（id=%d）: %v", id, err)
	}
}

// VerifyEmailCode 校验并消费邮箱验证码。
//
// 一次性：校验通过即标记 used_at。失败累计到上限则整条作废，
// 防止 6 位码被暴力枚举。
func (s *Services) VerifyEmailCode(email, scene, code string) error {
	rec, err := s.checkEmailCode(s.DB, email, scene, code)
	if err != nil {
		return err
	}
	return s.consumeEmailCode(s.DB, rec.ID)
}

// checkEmailCode **只校验、不消费**，返回命中的验证码记录。
//
// 拆成「校验」与「消费」两步，是为了让调用方能自己决定消费发生在哪个事务里：
// 密码重置要把「消费验证码」和「更新密码」放进同一个事务，失败时一起回滚
// （否则验证码被标记已用、密码却没改，用户只能等冷却后重新申请）。
//
// 校验失败的计数（attempts）在这里就地累加，且**刻意不放进调用方的事务**：
// 它是防暴力枚举的关键，必须在校验失败后立即生效，不能跟着回滚。
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
		// 失败计数用**带条件的**自增，而不是「先读上限、再无条件 +1」。
		//
		// 后者在并发下会漏：多个请求同时读到「还没到上限」的旧值，各自继续
		// 校验，同一个 6 位码就能被猜超过规定的次数。带条件时数据库保证只有
		// 一个能把它从「未达上限」推到下一格，推不动就说明已经到顶了。
		//
		// 用 s.DB 而不是传入的 db：即使调用方的事务随后回滚，这次失败也要留下。
		res := s.DB.Model(&model.EmailCode{}).
			Where("id = ? AND attempts < ?", rec.ID, emailCodeMaxAttempts).
			Update("attempts", gorm.Expr("attempts + 1"))
		if res.Error != nil {
			// 计数没记上就**不能**当成普通的「验证码错误」返回。
			//
			// 否则只要让写库持续失败（打满连接池、把磁盘写满……），攻击者就能
			// 无限次猜码：每次失败都不计数，上限永远不会到。这里是拒绝继续
			// 校验、如实报服务错误，让用户稍后重试。
			//
			// 不把底层错误拼进对外消息（会泄露实现细节），只写日志。
			log.Printf("[emailcode] 记录失败次数出错，拒绝继续校验: %v", res.Error)
			return nil, ErrEmailCodeCheckFailed
		}
		if res.RowsAffected == 0 {
			// 条件没命中：并发请求已经把它顶到上限了。
			return nil, ErrEmailCodeAttempts
		}
		return nil, ErrEmailCodeWrong
	}
	return &rec, nil
}

// consumeEmailCode 消费一条验证码（标记已使用）。
//
// 条件里带上「未使用 + 未过期 + 未达尝试上限」：校验与消费之间可能插进别的
// 请求（并发猜测、或恰好跨过过期时刻），只按 id 更新会把这些检查绕过去
// ——一个已经该作废的验证码仍然能被用掉。
//
// 并发下也只有一个请求能把 used_at 从 NULL 改成功，另一个拿到 0 行并得到
// 「验证码不正确」：同一个码不能被用两次。
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
