package service

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

type SettingKey string

const (
	KeyRegisterEnabled      SettingKey = "register.enabled"
	KeyRegisterNeedInvite   SettingKey = "register.need_invite"
	KeyRegisterRequireEmail SettingKey = "register.require_email_verify"
	KeyRegisterTerms        SettingKey = "register.terms"
	KeyRegisterMaxPerIP     SettingKey = "register.max_per_ip_per_day"
	KeyRegisterBlockDomains SettingKey = "register.blocked_email_domains"
	KeyRegisterCaptcha      SettingKey = "register.captcha_enabled"

	KeyRegisterAllowDomains      SettingKey = "register.allowed_email_domains"
	KeyRegisterWhitelistOnly     SettingKey = "register.whitelist_only"
	KeyRegisterMaxPerDomain      SettingKey = "register.max_per_domain_per_day"
	KeyRegisterTrustedSkipLimits SettingKey = "register.trusted_domain_skip_limits"
	KeyRegisterNonWhitelistQuota SettingKey = "register.non_whitelist_quota"

	KeyLoginCaptchaAfter SettingKey = "login.captcha_after_failures"
	KeyLoginMaxPerMinute SettingKey = "login.max_per_minute"

	KeyAuditRetentionDays SettingKey = "audit.retention_days"
	KeyStepUpEnabled      SettingKey = "security.step_up_enabled"

	KeyOAuthGitHubEnabled      SettingKey = "oauth.github_enabled"
	KeyOAuthGitHubClientID     SettingKey = "oauth.github_client_id"
	KeyOAuthGitHubClientSecret SettingKey = "oauth.github_client_secret"
	KeyOAuthGoogleEnabled      SettingKey = "oauth.google_enabled"
	KeyOAuthGoogleClientID     SettingKey = "oauth.google_client_id"
	KeyOAuthGoogleClientSecret SettingKey = "oauth.google_client_secret"

	KeyAPIRatePerMinute SettingKey = "api.rate_limit_per_minute"
	KeyAPIRateBurst     SettingKey = "api.rate_limit_burst"

	KeySMTPEnabled  SettingKey = "smtp.enabled"
	KeySMTPHost     SettingKey = "smtp.host"
	KeySMTPPort     SettingKey = "smtp.port"
	KeySMTPTLS      SettingKey = "smtp.tls"
	KeySMTPUser     SettingKey = "smtp.user"
	KeySMTPPassword SettingKey = "smtp.password"
	KeySMTPFrom     SettingKey = "smtp.from"

	KeyPaymentEnabled   SettingKey = "payment.enabled"
	KeyPaymentProvider  SettingKey = "payment.provider"
	KeyPaymentAppID     SettingKey = "payment.app_id"
	KeyPaymentSecret    SettingKey = "payment.secret"
	KeyPaymentNotifyURL SettingKey = "payment.notify_url"
	KeyPaymentReturnURL SettingKey = "payment.return_url"
	KeyPaymentMinAmount SettingKey = "payment.min_amount"
	KeyPaymentMaxAmount SettingKey = "payment.max_amount"
	KeyPaymentProduct   SettingKey = "payment.product_name"

	KeyPortReserved        SettingKey = "port.reserved"
	KeyFirewallEnabled     SettingKey = "firewall.enabled"
	KeyFirewallAutoOpen    SettingKey = "firewall.auto_open"
	KeyFirewallAutoClose   SettingKey = "firewall.auto_close"
	KeyFirewallProtected   SettingKey = "firewall.protected_ports"
	KeyFirewallHelperAddr  SettingKey = "firewall.helper_addr"
	KeyFirewallHelperToken SettingKey = "firewall.helper_token"

	KeySiteName              SettingKey = "site.name"
	KeySiteSubtitle          SettingKey = "site.subtitle"
	KeySiteFrontendURL       SettingKey = "site.frontend_url"
	KeySiteLogo              SettingKey = "site.logo"
	KeySiteHomeContent       SettingKey = "site.home_content"
	KeySiteAnnouncement      SettingKey = "site.announcement"
	KeySiteICP               SettingKey = "site.icp"
	KeySiteClientDownloadURL SettingKey = "site.client_download_url"

	KeyGatewayHost SettingKey = "gateway.host"
	KeyGatewayPort SettingKey = "gateway.port"

	KeyDomainPanel         SettingKey = "domain.panel"
	KeyDomainTunnel        SettingKey = "domain.tunnel"
	KeyDomainACMEEmail     SettingKey = "domain.acme_email"
	KeyDomainDNSProvider   SettingKey = "domain.dns_provider"
	KeyDomainDNSCredential SettingKey = "domain.dns_credential"
	KeyDomainDNSArgs       SettingKey = "domain.dns_args"
	KeyDomainHTTPSMode     SettingKey = "domain.https_mode"
	KeyDomainExpectedIP    SettingKey = "domain.expected_ip"
	KeyDomainHelperAddr    SettingKey = "domain.helper_addr"
	KeyDomainHelperToken   SettingKey = "domain.helper_token"

	KeyDomainAppliedPanel  SettingKey = "domain.applied_panel"
	KeyDomainAppliedTunnel SettingKey = "domain.applied_tunnel"
	KeyDomainAppliedMode   SettingKey = "domain.applied_https_mode"

	KeyDomainAppliedDigest SettingKey = "domain.applied_digest"

	KeyTrafficBaselineReady SettingKey = "traffic.baseline_ready"

	KeyTrafficResetMarkReady SettingKey = "traffic.reset_mark_ready"
)

const SecretMask = "__UNCHANGED__"

type settingSpec struct {
	Key        SettingKey
	Secret     bool
	Internal   bool
	SingleLine bool
	Default    func(cfg *config.Config) string
}

var settingSpecs = []settingSpec{
	{Key: KeyRegisterEnabled, Default: func(*config.Config) string { return "true" }},
	{Key: KeyRegisterNeedInvite, Default: func(*config.Config) string { return "false" }},
	{Key: KeyRegisterRequireEmail, Default: func(*config.Config) string { return "true" }},
	{Key: KeyRegisterTerms, Default: defaultTerms},
	{Key: KeyRegisterMaxPerIP, Default: func(*config.Config) string { return "3" }},
	{Key: KeyRegisterBlockDomains, Default: func(*config.Config) string { return "" }},
	{Key: KeyRegisterCaptcha, Default: func(*config.Config) string { return "true" }},

	{Key: KeyRegisterAllowDomains, Default: func(*config.Config) string { return "" }},
	{Key: KeyRegisterWhitelistOnly, Default: func(*config.Config) string { return "false" }},
	{Key: KeyRegisterMaxPerDomain, Default: func(*config.Config) string { return "5" }},
	{Key: KeyRegisterTrustedSkipLimits, Default: func(*config.Config) string { return "true" }},
	{Key: KeyRegisterNonWhitelistQuota, Default: func(*config.Config) string { return "0" }},

	{Key: KeyLoginCaptchaAfter, Default: func(*config.Config) string { return "3" }},
	{Key: KeyLoginMaxPerMinute, Default: func(*config.Config) string { return "10" }},

	{Key: KeyAuditRetentionDays, Default: func(*config.Config) string { return "180" }},
	{Key: KeyStepUpEnabled, Default: func(*config.Config) string { return "false" }},

	{Key: KeyOAuthGitHubEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyOAuthGitHubClientID, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyOAuthGitHubClientSecret, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyOAuthGoogleEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyOAuthGoogleClientID, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyOAuthGoogleClientSecret, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},

	{Key: KeyAPIRatePerMinute, Default: func(*config.Config) string { return "120" }},
	{Key: KeyAPIRateBurst, Default: func(*config.Config) string { return "60" }},

	{Key: KeySMTPEnabled, Default: func(c *config.Config) string { return boolStr(c.SMTP.Enabled()) }},
	{Key: KeySMTPHost, Default: func(c *config.Config) string { return c.SMTP.Host }},
	{Key: KeySMTPPort, Default: func(c *config.Config) string { return strconv.Itoa(c.SMTP.Port) }},
	{Key: KeySMTPTLS, Default: func(c *config.Config) string { return c.SMTP.TLS }},
	{Key: KeySMTPUser, Default: func(c *config.Config) string { return c.SMTP.User }},
	{Key: KeySMTPPassword, Secret: true, Default: func(c *config.Config) string { return c.SMTP.Password }},
	{Key: KeySMTPFrom, Default: func(c *config.Config) string { return c.SMTP.From }},

	{Key: KeyPaymentEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyPaymentProvider, Default: func(*config.Config) string { return "easypay" }},
	{Key: KeyPaymentAppID, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentSecret, Secret: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentNotifyURL, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentReturnURL, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentMinAmount, Default: func(*config.Config) string { return "100" }},
	{Key: KeyPaymentMaxAmount, Default: func(*config.Config) string { return "1000000" }},
	{Key: KeyPaymentProduct, Default: func(*config.Config) string { return "余额充值" }},

	{Key: KeyPortReserved, Default: func(c *config.Config) string {
		return "22,80,443,3306,5432,6379,8080,8443"
	}},
	{Key: KeyFirewallEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyFirewallAutoOpen, Default: func(*config.Config) string { return "true" }},
	{Key: KeyFirewallAutoClose, Default: func(*config.Config) string { return "true" }},
	{Key: KeyFirewallHelperAddr, Default: func(*config.Config) string { return "http://127.0.0.1:7849" }},
	{Key: KeyFirewallHelperToken, Secret: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyFirewallProtected, Default: func(c *config.Config) string {
		parts := []string{"22", "80", "443"}
		if _, port, err := splitHostPortLoose(c.UserAddr); err == nil && port != "" {
			parts = append(parts, port)
		}
		return strings.Join(parts, ",")
	}},

	{Key: KeySiteName, Default: func(c *config.Config) string { return c.SMTP.SiteName }},
	{Key: KeySiteSubtitle, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteFrontendURL, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteLogo, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteHomeContent, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteAnnouncement, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteICP, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteClientDownloadURL, Default: func(*config.Config) string { return "" }},

	{Key: KeyGatewayHost, SingleLine: true, Default: func(c *config.Config) string { return c.GatewayHost }},
	{Key: KeyGatewayPort, Default: func(c *config.Config) string {
		p := c.GatewayPort
		if p <= 0 {
			p = 7001
		}
		return strconv.Itoa(p)
	}},

	{Key: KeyDomainPanel, SingleLine: true, Default: func(c *config.Config) string { return normalizeDomainValue(c.UserPublicURL) }},
	{Key: KeyDomainTunnel, SingleLine: true, Default: func(c *config.Config) string { return normalizeDomainValue(c.TunnelDomain) }},
	{Key: KeyDomainACMEEmail, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSProvider, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSCredential, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSArgs, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainHTTPSMode, SingleLine: true, Default: func(c *config.Config) string {
		if strings.EqualFold(strings.TrimSpace(c.HTTPSProxyMode), tlscfg.HTTPSModeE2E) {
			return tlscfg.HTTPSModeE2E
		}
		return tlscfg.HTTPSModeEdge
	}},
	{Key: KeyDomainExpectedIP, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainHelperAddr, SingleLine: true, Default: func(*config.Config) string { return "http://127.0.0.1:7850" }},
	{Key: KeyDomainHelperToken, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},

	{Key: KeyDomainAppliedPanel, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedTunnel, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedMode, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedDigest, Internal: true, Default: func(*config.Config) string { return "" }},

	{Key: KeyTrafficBaselineReady, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyTrafficResetMarkReady, Internal: true, Default: func(*config.Config) string { return "" }},
}

var settingByKey = func() map[SettingKey]settingSpec {
	m := make(map[SettingKey]settingSpec, len(settingSpecs))
	for _, s := range settingSpecs {
		m[s.Key] = s
	}
	return m
}()

type SettingStore struct {
	db     *gorm.DB
	cfg    *config.Config
	encKey string

	mu      sync.RWMutex
	vals    map[SettingKey]string
	present map[SettingKey]bool

	raw map[string]string

	reloadMu sync.Mutex
}

func NewSettingStore(db *gorm.DB, cfg *config.Config) *SettingStore {
	s := &SettingStore{
		db:      db,
		cfg:     cfg,
		encKey:  cfg.APIKeyEncKey,
		vals:    make(map[SettingKey]string, len(settingSpecs)),
		present: make(map[SettingKey]bool, len(settingSpecs)),
	}
	if err := s.Reload(); err != nil {
		log.Printf("[setting] 加载运行期配置失败，已回落到默认值: %v", err)
		s.applyDefaults()
	}
	return s
}

func (s *SettingStore) applyDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, spec := range settingSpecs {
		s.vals[spec.Key] = spec.Default(s.cfg)
		s.present[spec.Key] = false
	}
	s.raw = nil
}

func (s *SettingStore) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadLocked()
}

func (s *SettingStore) reloadLocked() error {
	stored, err := s.fetch()
	if err != nil {
		return err
	}
	s.apply(stored)
	return nil
}

func (s *SettingStore) ReloadIfChanged() (bool, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	stored, err := s.fetch()
	if err != nil {
		return false, err
	}
	s.mu.RLock()
	same := s.raw != nil && len(s.raw) == len(stored)
	if same {
		for k, v := range stored {
			if s.raw[k] != v {
				same = false
				break
			}
		}
	}
	s.mu.RUnlock()
	if same {
		return false, nil
	}
	s.apply(stored)
	return true, nil
}

func (s *SettingStore) fetch() (map[string]string, error) {
	rows := make([]model.Setting, 0, len(settingSpecs))
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	stored := make(map[string]string, len(rows))
	for _, r := range rows {
		stored[r.Key] = r.Value
	}
	return stored, nil
}

func (s *SettingStore) apply(stored map[string]string) {
	vals := make(map[SettingKey]string, len(settingSpecs))
	present := make(map[SettingKey]bool, len(settingSpecs))
	for _, spec := range settingSpecs {
		raw, ok := stored[string(spec.Key)]
		if !ok {
			vals[spec.Key] = spec.Default(s.cfg)
			continue
		}
		if spec.Secret {
			plain, err := auth.DecryptAPIKey(s.encKey, raw)
			if err != nil {
				log.Printf("[setting] 解密 %s 失败，已回落默认值: %v", spec.Key, err)
				vals[spec.Key] = spec.Default(s.cfg)
				continue
			}
			vals[spec.Key] = plain
		} else {
			vals[spec.Key] = raw
		}
		present[spec.Key] = true
	}

	s.mu.Lock()
	s.vals = vals
	s.present = present
	s.raw = stored
	s.mu.Unlock()
}

func (s *SettingStore) Get(k SettingKey) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vals[k]
}

func (s *SettingStore) Snapshot(keys ...SettingKey) (map[SettingKey]string, map[SettingKey]bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vals := make(map[SettingKey]string, len(keys))
	present := make(map[SettingKey]bool, len(keys))
	for _, k := range keys {
		vals[k] = s.vals[k]
		present[k] = s.present[k]
	}
	return vals, present
}

func (s *SettingStore) Bool(k SettingKey) bool {
	switch strings.ToLower(strings.TrimSpace(s.Get(k))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func (s *SettingStore) Int(k SettingKey) int {
	n, err := strconv.Atoi(strings.TrimSpace(s.Get(k)))
	if err != nil {
		return 0
	}
	return n
}

func (s *SettingStore) SetMany(in map[SettingKey]string) error {
	if len(in) == 0 {
		return nil
	}

	type pending struct {
		key    string
		value  string
		secret bool
	}
	var toWrite []pending

	for k, v := range in {
		spec, ok := settingByKey[k]
		if !ok {
			return fmt.Errorf("%w: 未知配置项 %s", ErrInvalidParam, k)
		}
		if spec.Internal {
			return fmt.Errorf("%w: %s 由系统维护，不能手工修改", ErrInvalidParam, k)
		}
		if spec.Secret && v == SecretMask {
			continue
		}
		if spec.SingleLine && tlscfg.HasControlChars(v) {
			return fmt.Errorf("%w: %s 的值不能包含换行或其他控制字符", ErrInvalidParam, k)
		}
		stored := v
		if spec.Secret {
			enc, err := auth.EncryptAPIKey(s.encKey, v)
			if err != nil {
				return fmt.Errorf("加密配置 %s 失败: %w", k, err)
			}
			stored = enc
		}
		toWrite = append(toWrite, pending{key: string(k), value: stored, secret: spec.Secret})
	}
	if len(toWrite) == 0 {
		return nil
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	err := s.db.Transaction(func(tx *gorm.DB) error {
		for _, p := range toWrite {
			row := model.Setting{Key: p.key}
			if err := tx.Where("key = ?", p.key).Assign(model.Setting{Value: p.value}).
				FirstOrCreate(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.reloadLocked()
}

func (s *SettingStore) SetInternal(in map[SettingKey]string) error {
	if len(in) == 0 {
		return nil
	}
	for k := range in {
		spec, ok := settingByKey[k]
		if !ok || !spec.Internal {
			return fmt.Errorf("%w: %s 不是系统维护项", ErrInvalidParam, k)
		}
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	err := s.db.Transaction(func(tx *gorm.DB) error {
		for k, v := range in {
			key := string(k)
			row := model.Setting{Key: key}
			if err := tx.Where("key = ?", key).Assign(model.Setting{Value: v}).
				FirstOrCreate(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.reloadLocked()
}

func (s *SettingStore) hasRow(k SettingKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.present[k]
}

func (s *Services) ReloadSettingsIfChanged() {
	if !s.domainMu.TryLock() {
		return
	}
	defer s.domainMu.Unlock()

	changed, err := s.Settings.ReloadIfChanged()
	if err != nil {
		return
	}
	if changed {
		log.Printf("[setting] 检测到其他实例修改了运行期配置，已重新载入")
	}
}

func (s *SettingStore) AllForAdmin() map[string]string {
	out := make(map[string]string, len(settingSpecs))
	for _, spec := range settingSpecs {
		if spec.Internal {
			continue
		}
		v := s.Get(spec.Key)
		if spec.Secret {
			if v == "" {
				out[string(spec.Key)] = ""
			} else {
				out[string(spec.Key)] = SecretMask
			}
			continue
		}
		out[string(spec.Key)] = v
	}
	return out
}
