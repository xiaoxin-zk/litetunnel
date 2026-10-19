package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/controlplane"
	"github.com/xiaoxin-zk/litetunnel/server/internal/mailer"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/monitor"
)

const (
	loginLockThreshold = 3
	loginLockBase      = 30 * time.Minute
	loginLockMax       = 24 * time.Hour
)

var (
	ErrNotFound            = errors.New("资源不存在")
	ErrBadCredentials      = errors.New("用户名或密码错误")
	ErrUsernameTaken       = errors.New("该用户名已被占用")
	ErrAccountDisabled     = errors.New("账号已被禁用，请联系管理员")
	ErrQuotaExceeded       = errors.New("流量额度已用尽，请兑换或联系管理员")
	ErrTunnelLimit         = errors.New("已达到当前分组的隧道数量上限")
	ErrPortLimit           = errors.New("已达到当前分组的端口数量上限")
	ErrNoPortAvailable     = errors.New("端口池已耗尽，请稍后重试")
	ErrPortInUse           = errors.New("该远程端口已被占用")
	ErrPortScanUnavailable = errors.New("暂时无法读取系统端口占用情况，请稍后重试")
	ErrProtocolDenied      = errors.New("当前分组不允许使用该协议")
	ErrDomainDenied        = errors.New("当前分组不允许使用自定义域名")
	ErrCodeInvalid         = errors.New("兑换码无效")
	ErrCodeUsed            = errors.New("兑换码已被使用")
	ErrCodeExpired         = errors.New("兑换码已过期")
	ErrCodeDisabled        = errors.New("兑换码已被禁用")
	ErrInvalidParam        = errors.New("参数不合法")

	ErrMembershipExpired = errors.New("当前分组有效期已过期")

	ErrTOTPRequired = errors.New("该账号已启用双因素认证，请输入动态口令")
	ErrTOTPInvalid  = errors.New("动态口令不正确")
	ErrTOTPReplay   = errors.New("该动态口令已被使用过，请等待认证器刷新后重试")

	ErrRegisterClosed           = errors.New("本站已关闭注册，请联系管理员开通账号")
	ErrCaptchaInvalid           = errors.New("验证码不正确或已过期，请重新获取")
	ErrRegisterLimited          = errors.New("当前网络注册过于频繁，请稍后再试")
	ErrEmailNotAllowed          = errors.New("该邮箱域名不允许注册")
	ErrDomainNotTrusted         = errors.New("本站当前仅允许白名单内的邮箱域名注册")
	ErrDomainRegisterLimited    = errors.New("该邮箱域名今日注册数量已达上限，请改用其他邮箱或明日再试")
	ErrNonWhitelistQuota        = errors.New("该邮箱域名不在白名单内，且注册名额已用尽")
	ErrEmailCodeNeeded          = errors.New("请输入邮箱验证码")
	ErrEmailCodeWrong           = errors.New("邮箱验证码不正确或已过期")
	ErrEmailCodeCheckFailed     = errors.New("验证码校验暂时不可用，请稍后重试")
	ErrFirewallQueueFull        = errors.New("防火墙待办队列已满，端口操作无法排队重试")
	ErrFirewallQueueUnavailable = errors.New("防火墙待办队列不可用（数据库故障），端口操作无法持久化重试")
	ErrFirewallStateUnknown     = errors.New("防火墙目标状态未知，意图已保留待重试")

	ErrEmailRequired     = errors.New("请填写有效的邮箱地址")
	ErrEmailTaken        = errors.New("该邮箱已被其他账号使用")
	ErrEmailCodeTooSoon  = errors.New("验证码发送过于频繁，请稍后再试")
	ErrEmailCodeTooMany  = errors.New("该邮箱今日验证码发送次数已达上限，请明日再试")
	ErrEmailCodeAttempts = errors.New("验证码错误次数过多，请重新获取")
)

type Services struct {
	DB      *gorm.DB
	Cfg     *config.Config
	Frps    *FrpsClient
	Control *controlplane.Client
	Runtime *Runtime

	Settings *SettingStore

	Captchas *CaptchaStore

	LoginGuard *middleware.LoginGuard

	Monitor *monitor.Collector

	loginLogCh chan model.LoginLog

	loginFails loginFailCounter

	mailWake         chan struct{}
	recoveryCh       chan recoveryRequest
	recoveryCounters *recoveryCounters
	mailerOverride   mailSender

	fwMu       sync.Mutex
	fwPending  map[int]pendingFW
	fwReserved int

	drainFallback *proxyDrainFallbackQueue

	drainRaceSuspects atomic.Int64
	drainRaceMu       sync.Mutex
	drainRaceRecent   []string

	userLocks [userLockShards]sync.Mutex

	portLocks [portLockShards]sync.Mutex

	statusGenMu sync.Mutex
	statusGens  map[uint]userStatusEntry

	adminMu sync.Mutex

	domainMu sync.Mutex

	fwKick chan struct{}

	instanceID string

	collectorOwned atomic.Bool

	guardFullAt atomic.Int64

	auditCounters *auditCounters

	updateMu    sync.Mutex
	updateCache *UpdateStatus

	blockMu    sync.Mutex
	blockRaw   string
	blockCache []netip.Prefix
	blockAt    time.Time
}

const portLockShards = 64

func (s *Services) portLock(port int) *sync.Mutex {
	if port < 0 {
		port = -port
	}
	return &s.portLocks[port%portLockShards]
}

func (s *Services) KickFirewall() {
	if s.fwKick == nil {
		return
	}
	select {
	case s.fwKick <- struct{}{}:
	default:
	}
}

const userLockShards = 64

func (s *Services) userLock(userID uint) *sync.Mutex {
	return &s.userLocks[userID%userLockShards]
}

func New(db *gorm.DB, cfg *config.Config) *Services {
	control := mustControlPlane(cfg)
	return &Services{
		DB:         db,
		Cfg:        cfg,
		Frps:       NewFrpsClient(cfg),
		Control:    control,
		Runtime:    newRuntime(control),
		Settings:   NewSettingStore(db, cfg),
		Captchas:   NewCaptchaStore(),
		LoginGuard: middleware.NewLoginGuard(loginLockThreshold, loginLockBase, loginLockMax),

		instanceID: newInstanceID(),

		Monitor:          monitor.New(cfg.MonitorDiskPath),
		loginLogCh:       make(chan model.LoginLog, loginLogBuffer),
		loginFails:       newLoginFailureCounter(db),
		mailWake:         make(chan struct{}, 1),
		recoveryCh:       make(chan recoveryRequest, recoveryBuffer),
		recoveryCounters: &recoveryCounters{},
		fwPending:        map[int]pendingFW{},
		fwKick:           make(chan struct{}, 1),
		drainFallback:    newProxyDrainFallbackQueue(),
		statusGens:       map[uint]userStatusEntry{},
		auditCounters:    &auditCounters{},
	}
}

func (s *Services) Close() {
	if s == nil {
		return
	}
	s.Captchas.Close()
	s.LoginGuard.Close()
}

func newInstanceID() string {
	if id, err := randomHex(8); err == nil {
		return id
	}
	return fmt.Sprintf("t%d", time.Now().UnixNano())
}

type mailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

func (s *Services) mailSender() mailSender {
	if s.mailerOverride != nil {
		return s.mailerOverride
	}
	return s.Mailer()
}

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

func (s *Services) Mailer() *mailer.Mailer { return mailer.New(s.SMTPConfig()) }

func (s *Services) MailEnabled() bool {
	if !s.Settings.Bool(KeySMTPEnabled) {
		return false
	}
	return s.SMTPConfig().Enabled()
}

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

func (s *Services) EffectiveBandwidth(u *model.User) int64 {
	if g := s.EffectiveGroup(u); g != nil {
		return g.BandwidthLimit
	}
	return 0
}

func (s *Services) defaultGroup() *model.Group {
	var g model.Group
	if err := s.DB.Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

func (s *Services) EffectiveQuota(u *model.User) int64 {
	if u.TrafficQuota > 0 {
		return u.TrafficQuota
	}
	if g := s.EffectiveGroup(u); g != nil {
		return g.TrafficQuota
	}
	return 0
}

func (s *Services) QuotaExceeded(u *model.User) bool {
	q := s.EffectiveQuota(u)
	return q > 0 && u.TrafficUsed >= q
}

func (s *Services) EnsureTrafficPeriod(u *model.User) {
	if u == nil || u.ID == 0 {
		return
	}
	now := time.Now()
	if u.TrafficResetAt.IsZero() {
		next := now.AddDate(0, 1, 0)
		res := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
			Update("traffic_reset_at", next)
		if res.Error != nil {
			log.Printf("[quota] 初始化流量周期失败（用户 %d），下轮重试: %v", u.ID, res.Error)
			return
		}
		u.TrafficResetAt = next
		return
	}
	if now.Before(u.TrafficResetAt) {
		return
	}
	next := u.TrafficResetAt
	for !next.After(now) {
		next = next.AddDate(0, 1, 0)
	}
	res := s.DB.Model(&model.User{}).
		Where("id = ? AND traffic_reset_at = ?", u.ID, u.TrafficResetAt).
		Updates(map[string]any{
			"traffic_used":     0,
			"traffic_reset_at": next,
		})
	if res.Error != nil {
		log.Printf("[quota] 流量周期重置失败（用户 %d），保持原状态下轮重试: %v", u.ID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		var fresh model.User
		if err := s.DB.Preload("Group").First(&fresh, u.ID).Error; err == nil {
			*u = fresh
		}
		return
	}
	u.TrafficUsed = 0
	u.TrafficResetAt = next
}

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

func (s *Services) ResolveUserIdentity(id uint) (active bool, tokenVersion int) {
	for attempt := 0; attempt < 2; attempt++ {
		if a, v, ok := s.Runtime.CachedIdentity(IdentityKindUser, id); ok {
			return a, v
		}
		gen := s.Runtime.IdentityGen(IdentityKindUser, id)
		u, err := s.LoadUser(id)
		if err != nil {
			if s.Runtime.SetCachedIdentityIfGen(IdentityKindUser, id, false, 0, gen) {
				return false, 0
			}
			continue
		}
		a := u.Status == model.UserStatusActive
		if s.Runtime.SetCachedIdentityIfGen(IdentityKindUser, id, a, u.TokenVersion, gen) {
			return a, u.TokenVersion
		}
	}
	return false, 0
}

func (s *Services) ResolveAdminIdentity(id uint) (active bool, tokenVersion int) {
	for attempt := 0; attempt < 2; attempt++ {
		if a, v, ok := s.Runtime.CachedIdentity(IdentityKindAdmin, id); ok {
			return a, v
		}
		gen := s.Runtime.IdentityGen(IdentityKindAdmin, id)
		adm, err := s.LoadAdmin(id)
		if err != nil {
			if s.Runtime.SetCachedIdentityIfGen(IdentityKindAdmin, id, false, 0, gen) {
				return false, 0
			}
			continue
		}
		a := adm.Status == "active"
		if s.Runtime.SetCachedIdentityIfGen(IdentityKindAdmin, id, a, adm.TokenVersion, gen) {
			return a, adm.TokenVersion
		}
	}
	return false, 0
}

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

func FormatBandwidthHuman(bitsPerSec int64) string {
	if bitsPerSec <= 0 {
		return ""
	}
	const (
		k = 1024.0
		m = 1024.0 * 1024.0
	)
	b := float64(bitsPerSec)
	switch {
	case b >= m:
		return strconv.FormatFloat(b/m, 'f', -1, 64) + " Mbps"
	case b >= k:
		return strconv.FormatFloat(b/k, 'f', -1, 64) + " Kbps"
	default:
		return strconv.FormatInt(bitsPerSec, 10) + " bps"
	}
}

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
		return "1.00KB"
	}
	return strconv.FormatFloat(bytesPerSec/kb, 'f', 2, 64) + "KB"
}

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
