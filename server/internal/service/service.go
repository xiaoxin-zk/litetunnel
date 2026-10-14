// Package service 承载控制面的全部业务逻辑。
//
// 设计要点：
//   - 权限与配额只在服务端计算，客户端提交的任何额度声明都不被信任；
//   - 所有对外返回的用户对象都不包含口令与密钥哈希（模型已用 json:"-" 保证）。
package service

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/mailer"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 业务错误。处理器统一映射为 HTTP 状态码。
var (
	ErrNotFound        = errors.New("资源不存在")
	ErrBadCredentials  = errors.New("用户名或密码错误")
	ErrUsernameTaken   = errors.New("该用户名已被占用")
	ErrAccountDisabled = errors.New("账号已被禁用，请联系管理员")
	ErrQuotaExceeded   = errors.New("流量额度已用尽，请兑换或联系管理员")
	ErrTunnelLimit     = errors.New("已达到当前分组的隧道数量上限")
	ErrPortLimit       = errors.New("已达到当前分组的端口数量上限")
	ErrNoPortAvailable = errors.New("端口池已耗尽，请稍后重试")
	ErrPortInUse       = errors.New("该远程端口已被占用")
	ErrProtocolDenied  = errors.New("当前分组不允许使用该协议")
	ErrDomainDenied    = errors.New("当前分组不允许使用自定义域名")
	ErrCodeInvalid     = errors.New("兑换码无效")
	ErrCodeUsed        = errors.New("兑换码已被使用")
	ErrCodeExpired     = errors.New("兑换码已过期")
	ErrCodeDisabled    = errors.New("兑换码已被禁用")
	ErrInvalidParam    = errors.New("参数不合法")

	// ErrTOTPRequired 表示账号已启用双因素认证但本次未提交动态口令。
	// 与 ErrTOTPInvalid 区分开：前者只是没填，不应计入暴力破解次数。
	ErrTOTPRequired = errors.New("该账号已启用双因素认证，请输入动态口令")
	ErrTOTPInvalid  = errors.New("动态口令不正确")
	// ErrTOTPReplay 表示该动态口令在有效窗口内已被使用过。
	// 正常用户不会碰到（认证器每 30 秒换一个码），出现即意味着有人在重放。
	ErrTOTPReplay = errors.New("该动态口令已被使用过，请等待认证器刷新后重试")

	// 注册准入相关
	ErrRegisterClosed  = errors.New("本站已关闭注册，请联系管理员开通账号")
	ErrCaptchaInvalid  = errors.New("验证码不正确或已过期，请重新获取")
	ErrRegisterLimited = errors.New("当前网络注册过于频繁，请稍后再试")
	ErrEmailNotAllowed = errors.New("该邮箱域名不允许注册")
	// ErrDomainNotTrusted 表示站点开启了「仅白名单域名可注册」。
	ErrDomainNotTrusted = errors.New("本站当前仅允许白名单内的邮箱域名注册")
	// ErrDomainRegisterLimited 表示该邮箱域名当日注册量已达上限。
	ErrDomainRegisterLimited = errors.New("该邮箱域名今日注册数量已达上限，请改用其他邮箱或明日再试")
	ErrEmailCodeNeeded = errors.New("请输入邮箱验证码")
	ErrEmailCodeWrong  = errors.New("邮箱验证码不正确或已过期")

	// 邮箱验证码相关
	ErrEmailRequired     = errors.New("请填写有效的邮箱地址")
	ErrEmailTaken        = errors.New("该邮箱已被其他账号使用")
	ErrEmailCodeTooSoon  = errors.New("验证码发送过于频繁，请稍后再试")
	ErrEmailCodeTooMany  = errors.New("该邮箱今日验证码发送次数已达上限，请明日再试")
	ErrEmailCodeAttempts = errors.New("验证码错误次数过多，请重新获取")
)

// Services 业务服务集合。
type Services struct {
	DB      *gorm.DB
	Cfg     *config.Config
	Frps    *FrpsClient
	Runtime *Runtime

	// Settings 是管理端可随时调整的运行期配置（SMTP、注册开关、支付、端口策略）。
	// 与 Cfg 的分工见 setting.go 的注释。
	Settings *SettingStore

	// Captchas 是内存中的一次性验证码存储。
	Captchas *CaptchaStore

	// TOTPReplay 记录已用过的动态口令步进码，阻止窗口内重放。
	TOTPReplay *TOTPReplayGuard

	// loginLogCh 与 mailCh 都是异步队列：
	// 登录日志不能阻塞登录判定，邮件投递不能因为 SMTP 往返而暴露账号是否存在。
	loginLogCh chan model.LoginLog
	mailCh     chan outboundMail
}

// New 构造服务集合。
func New(db *gorm.DB, cfg *config.Config) *Services {
	return &Services{
		DB:         db,
		Cfg:        cfg,
		Frps:       NewFrpsClient(cfg),
		Runtime:    NewRuntime(),
		Settings:   NewSettingStore(db, cfg),
		Captchas:   NewCaptchaStore(),
		TOTPReplay: NewTOTPReplayGuard(),
		loginLogCh: make(chan model.LoginLog, loginLogBuffer),
		mailCh:     make(chan outboundMail, mailQueueSize),
	}
}

// SMTPConfig 按当前运行期配置组装邮件参数。
//
// 邮件配置可在管理端随时修改，因此每次都重新组装而不是启动时固定。
func (s *Services) SMTPConfig() config.SMTPConfig {
	return config.SMTPConfig{
		Host:     strings.TrimSpace(s.Settings.Get(KeySMTPHost)),
		Port:     s.Settings.Int(KeySMTPPort),
		User:     strings.TrimSpace(s.Settings.Get(KeySMTPUser)),
		Password: s.Settings.Get(KeySMTPPassword),
		From:     strings.TrimSpace(s.Settings.Get(KeySMTPFrom)),
		TLS:      strings.ToLower(strings.TrimSpace(s.Settings.Get(KeySMTPTLS))),
		SiteName: s.Settings.Get(KeySiteName),
	}
}

// Mailer 按当前配置构造发信器。
func (s *Services) Mailer() *mailer.Mailer { return mailer.New(s.SMTPConfig()) }

// MailEnabled 返回当前是否启用了邮件发送。
//
// 需要同时满足「管理端开关打开」与「参数齐全」两个条件：
// 只填了参数但开关没开，不应静默发信。
func (s *Services) MailEnabled() bool {
	if !s.Settings.Bool(KeySMTPEnabled) {
		return false
	}
	return s.SMTPConfig().Enabled()
}

// EffectiveGroup 返回用户当前生效的分组。
// 分组已过期或未绑定时，回落到系统默认分组，避免出现无限制的越权状态。
func (s *Services) EffectiveGroup(u *model.User) *model.Group {
	if u == nil {
		return nil
	}
	if u.GroupExpireAt != nil && u.GroupExpireAt.Before(time.Now()) {
		return s.defaultGroup()
	}
	if u.Group != nil {
		return u.Group
	}
	return s.defaultGroup()
}

func (s *Services) defaultGroup() *model.Group {
	var g model.Group
	if err := s.DB.Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

// EffectiveQuota 返回用户本计费周期的流量配额（字节）。0 表示不限。
func (s *Services) EffectiveQuota(u *model.User) int64 {
	if u.TrafficQuota > 0 {
		return u.TrafficQuota
	}
	if g := s.EffectiveGroup(u); g != nil {
		return g.TrafficQuota
	}
	return 0
}

// QuotaExceeded 判断用户是否已超额。
func (s *Services) QuotaExceeded(u *model.User) bool {
	q := s.EffectiveQuota(u)
	return q > 0 && u.TrafficUsed >= q
}

// EnsureTrafficPeriod 在跨计费周期时重置已用流量。
// 采用惰性重置，避免额外的定时任务。
func (s *Services) EnsureTrafficPeriod(u *model.User) {
	if u == nil {
		return
	}
	now := time.Now()
	if u.TrafficResetAt.IsZero() {
		next := now.AddDate(0, 1, 0)
		u.TrafficResetAt = next
		_ = s.DB.Model(&model.User{}).Where("id = ?", u.ID).
			Update("traffic_reset_at", next).Error
		return
	}
	if now.Before(u.TrafficResetAt) {
		return
	}
	// 周期结束：重置已用量并顺延到下一个周期。
	next := u.TrafficResetAt
	for !next.After(now) {
		next = next.AddDate(0, 1, 0)
	}
	u.TrafficUsed = 0
	u.TrafficResetAt = next
	_ = s.DB.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"traffic_used":     0,
		"traffic_reset_at": next,
	}).Error
}

// ResolveCredential 把长期凭据解析为身份，供桌面客户端使用。
//
// 依次尝试 API Key（SHA-256 摘要比对）与客户端接入凭据（常量时间比对）。
// 两者都可独立吊销，因此客户端无需在本地保存账号密码。
func (s *Services) ResolveCredential(plain string) (uint, string, error) {
	if plain == "" {
		return 0, "", ErrNotFound
	}
	if u, err := s.LoadUserByAPIKey(plain); err == nil {
		return u.ID, u.Username, nil
	}
	if u, err := s.LoadUserByClientSecret(plain); err == nil {
		return u.ID, u.Username, nil
	}
	return 0, "", ErrNotFound
}

// ResolveUserIdentity 返回用户的实时状态：是否有效 + 当前令牌版本。
//
// 用于每次请求时校验令牌持有者：仅验签无法发现账号已被禁用，
// 也无法发现密码已被重置（此时令牌版本自增，旧令牌必须失效）。
func (s *Services) ResolveUserIdentity(id uint) (active bool, tokenVersion int) {
	if a, v, ok := s.Runtime.CachedIdentity(IdentityKindUser, id); ok {
		return a, v
	}
	u, err := s.LoadUser(id)
	if err != nil {
		s.Runtime.SetCachedIdentity(IdentityKindUser, id, false, 0)
		return false, 0
	}
	active = u.Status == model.UserStatusActive
	s.Runtime.SetCachedIdentity(IdentityKindUser, id, active, u.TokenVersion)
	return active, u.TokenVersion
}

// ResolveAdminIdentity 返回管理员的实时状态。
func (s *Services) ResolveAdminIdentity(id uint) (active bool, tokenVersion int) {
	if a, v, ok := s.Runtime.CachedIdentity(IdentityKindAdmin, id); ok {
		return a, v
	}
	adm, err := s.LoadAdmin(id)
	if err != nil {
		s.Runtime.SetCachedIdentity(IdentityKindAdmin, id, false, 0)
		return false, 0
	}
	active = adm.Status == "active"
	s.Runtime.SetCachedIdentity(IdentityKindAdmin, id, active, adm.TokenVersion)
	return active, adm.TokenVersion
}

// AllowedProtocols 解析分组允许的协议集合。
func AllowedProtocols(g *model.Group) map[string]bool {
	out := map[string]bool{}
	if g == nil {
		return out
	}
	for _, p := range strings.Split(g.AllowProtocols, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// FormatBandwidth 将 bit/s 转为 frp 可识别的限速字符串。
//
// 注意：frp 的 BandwidthQuantity 仅接受 "MB" 与 "KB" 后缀，
// 且语义为「字节/秒」。因此这里必须先除以 8 再格式化。
func FormatBandwidth(bitsPerSec int64) string {
	if bitsPerSec <= 0 {
		return ""
	}
	bytesPerSec := float64(bitsPerSec) / 8.0
	const (
		kb = 1024.0
		mb = 1024.0 * 1024.0
	)
	if bytesPerSec >= mb {
		return strconv.FormatFloat(bytesPerSec/mb, 'f', 2, 64) + "MB"
	}
	if bytesPerSec < kb {
		// 低于 1KB/s 的限速在 frp 侧无意义，统一抬到 1KB/s，避免解析为 0（不限速）。
		return "1.00KB"
	}
	return strconv.FormatFloat(bytesPerSec/kb, 'f', 2, 64) + "KB"
}

// FormatBytes 人类可读的流量体积。
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}
