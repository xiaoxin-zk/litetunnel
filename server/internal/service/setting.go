package service

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// SettingKey 是管理端可随时调整的运行期配置项。
//
// 与 config.Config 的分工：
//   - config.Config：部署期确定、由环境变量注入（监听地址、JWT 密钥、数据库路径）
//   - SettingKey：运营期需要随时改（注册开关、SMTP、支付、端口与防火墙策略）
//
// 后者存数据库，敏感字段用 AES-256-GCM 加密。
// 环境变量中的同名值作为「初始默认值」：数据库没有记录时回落到环境变量，
// 这样既能用 .env 快速部署，又能在界面里改。
type SettingKey string

const (
	// ---- 注册与准入 ----
	KeyRegisterEnabled      SettingKey = "register.enabled"
	KeyRegisterNeedInvite   SettingKey = "register.need_invite"
	KeyRegisterRequireEmail SettingKey = "register.require_email_verify"
	KeyRegisterTerms        SettingKey = "register.terms"
	KeyRegisterMaxPerIP     SettingKey = "register.max_per_ip_per_day"
	KeyRegisterBlockDomains SettingKey = "register.blocked_email_domains"
	KeyRegisterCaptcha      SettingKey = "register.captcha_enabled"

	// 邮箱域名白名单与差异化准入。
	//
	// 典型用法：把企业自有域名（如 company.com）列入白名单，员工可自由注册；
	// 其余公共邮箱域名仍可注册，但受「单域名每日上限」约束，
	// 避免有人用临时邮箱批量刷账号。
	KeyRegisterAllowDomains      SettingKey = "register.allowed_email_domains"
	KeyRegisterWhitelistOnly     SettingKey = "register.whitelist_only"
	KeyRegisterMaxPerDomain      SettingKey = "register.max_per_domain_per_day"
	KeyRegisterTrustedSkipLimits SettingKey = "register.trusted_domain_skip_limits"

	// ---- 登录防护 ----
	KeyLoginCaptchaAfter SettingKey = "login.captcha_after_failures"
	KeyLoginMaxPerMinute SettingKey = "login.max_per_minute"

	// ---- 面板接口限流 ----
	//
	// 针对已认证接口的通用限流，按账号维度计数（未认证请求按 IP）。
	// 与登录限流分开配置：登录需要严，正常业务接口太严会误伤。
	KeyAPIRatePerMinute SettingKey = "api.rate_limit_per_minute"
	KeyAPIRateBurst     SettingKey = "api.rate_limit_burst"

	// ---- 邮件 ----
	KeySMTPEnabled  SettingKey = "smtp.enabled"
	KeySMTPHost     SettingKey = "smtp.host"
	KeySMTPPort     SettingKey = "smtp.port"
	KeySMTPTLS      SettingKey = "smtp.tls"
	KeySMTPUser     SettingKey = "smtp.user"
	KeySMTPPassword SettingKey = "smtp.password"
	KeySMTPFrom     SettingKey = "smtp.from"

	// ---- 支付（当前仅保存配置，未接入实际渠道）----
	KeyPaymentEnabled   SettingKey = "payment.enabled"
	KeyPaymentProvider  SettingKey = "payment.provider"
	KeyPaymentAppID     SettingKey = "payment.app_id"
	KeyPaymentSecret    SettingKey = "payment.secret"
	KeyPaymentNotifyURL SettingKey = "payment.notify_url"
	KeyPaymentReturnURL SettingKey = "payment.return_url"
	KeyPaymentMinAmount SettingKey = "payment.min_amount"
	KeyPaymentMaxAmount SettingKey = "payment.max_amount"
	KeyPaymentProduct   SettingKey = "payment.product_name"

	// ---- 端口与防火墙 ----
	KeyPortReserved      SettingKey = "port.reserved"
	KeyFirewallEnabled   SettingKey = "firewall.enabled"
	KeyFirewallBackend   SettingKey = "firewall.backend"
	KeyFirewallAutoOpen  SettingKey = "firewall.auto_open"
	KeyFirewallProtected SettingKey = "firewall.protected_ports"

	// ---- 站点 ----
	KeySiteName         SettingKey = "site.name"
	KeySiteAnnouncement SettingKey = "site.announcement"
	KeySiteICP          SettingKey = "site.icp"
)

// SecretMask 是敏感字段回显给前端时的占位符。
//
// 管理员保存设置时如果原样提交了该占位符，表示「不修改此项」，
// 这样界面上就不必把明文密钥再传一遍。
const SecretMask = "__UNCHANGED__"

// settingSpec 描述一个配置项的默认值来源与是否加密。
type settingSpec struct {
	Key    SettingKey
	Secret bool
	// Default 是数据库无记录时的回落值，通常来自环境变量。
	Default func(cfg *config.Config) string
}

// settingSpecs 是全部可配置项的白名单。
//
// 用白名单而非自由 key-value：避免接口被用来往设置表里塞任意键，
// 也保证每项都有明确的默认值。
var settingSpecs = []settingSpec{
	// 注册与准入
	{Key: KeyRegisterEnabled, Default: func(*config.Config) string { return "true" }},
	{Key: KeyRegisterNeedInvite, Default: func(*config.Config) string { return "false" }},
	// 默认 true：只要站点启用了邮件，注册就必须验证邮箱。
	// 邮件未启用时该项不生效（没有发信通道，强制验证只会把用户挡在门外）。
	{Key: KeyRegisterRequireEmail, Default: func(*config.Config) string { return "true" }},
	{Key: KeyRegisterTerms, Default: defaultTerms},
	{Key: KeyRegisterMaxPerIP, Default: func(*config.Config) string { return "3" }},
	{Key: KeyRegisterBlockDomains, Default: func(*config.Config) string { return "" }},
	{Key: KeyRegisterCaptcha, Default: func(*config.Config) string { return "true" }},

	// 邮箱域名白名单与差异化准入
	{Key: KeyRegisterAllowDomains, Default: func(*config.Config) string { return "" }},
	{Key: KeyRegisterWhitelistOnly, Default: func(*config.Config) string { return "false" }},
	{Key: KeyRegisterMaxPerDomain, Default: func(*config.Config) string { return "5" }},
	{Key: KeyRegisterTrustedSkipLimits, Default: func(*config.Config) string { return "true" }},

	// 登录防护
	{Key: KeyLoginCaptchaAfter, Default: func(*config.Config) string { return "3" }},
	{Key: KeyLoginMaxPerMinute, Default: func(*config.Config) string { return "10" }},

	// 面板接口限流
	{Key: KeyAPIRatePerMinute, Default: func(*config.Config) string { return "120" }},
	{Key: KeyAPIRateBurst, Default: func(*config.Config) string { return "60" }},

	// 邮件：默认值取自环境变量，便于用 .env 快速部署
	{Key: KeySMTPEnabled, Default: func(c *config.Config) string { return boolStr(c.SMTP.Enabled()) }},
	{Key: KeySMTPHost, Default: func(c *config.Config) string { return c.SMTP.Host }},
	{Key: KeySMTPPort, Default: func(c *config.Config) string { return strconv.Itoa(c.SMTP.Port) }},
	{Key: KeySMTPTLS, Default: func(c *config.Config) string { return c.SMTP.TLS }},
	{Key: KeySMTPUser, Default: func(c *config.Config) string { return c.SMTP.User }},
	{Key: KeySMTPPassword, Secret: true, Default: func(c *config.Config) string { return c.SMTP.Password }},
	{Key: KeySMTPFrom, Default: func(c *config.Config) string { return c.SMTP.From }},

	// 支付（仅配置）
	{Key: KeyPaymentEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyPaymentProvider, Default: func(*config.Config) string { return "easypay" }},
	{Key: KeyPaymentAppID, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentSecret, Secret: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentNotifyURL, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentReturnURL, Default: func(*config.Config) string { return "" }},
	{Key: KeyPaymentMinAmount, Default: func(*config.Config) string { return "100" }},
	{Key: KeyPaymentMaxAmount, Default: func(*config.Config) string { return "1000000" }},
	{Key: KeyPaymentProduct, Default: func(*config.Config) string { return "余额充值" }},

	// 端口与防火墙
	{Key: KeyPortReserved, Default: func(c *config.Config) string {
		// 默认把最常见的系统端口列为保留，避免误分配给用户隧道。
		return "22,80,443,3306,5432,6379,8080,8443"
	}},
	{Key: KeyFirewallEnabled, Default: func(*config.Config) string { return "false" }},
	{Key: KeyFirewallBackend, Default: func(*config.Config) string { return "auto" }},
	{Key: KeyFirewallAutoOpen, Default: func(*config.Config) string { return "true" }},
	{Key: KeyFirewallProtected, Default: func(c *config.Config) string {
		// 这些端口永远不会被面板关闭，防止把自己锁在门外。
		parts := []string{"22", "80", "443"}
		if _, port, err := splitHostPortLoose(c.UserAddr); err == nil && port != "" {
			parts = append(parts, port)
		}
		return strings.Join(parts, ",")
	}},

	// 站点
	{Key: KeySiteName, Default: func(c *config.Config) string { return c.SMTP.SiteName }},
	{Key: KeySiteAnnouncement, Default: func(*config.Config) string { return "" }},
	{Key: KeySiteICP, Default: func(*config.Config) string { return "" }},
}

// settingByKey 便于 O(1) 查找白名单项。
var settingByKey = func() map[SettingKey]settingSpec {
	m := make(map[SettingKey]settingSpec, len(settingSpecs))
	for _, s := range settingSpecs {
		m[s.Key] = s
	}
	return m
}()

// SettingStore 提供带类型转换与透明加解密的运行期配置读写。
//
// 全部配置缓存在内存中：这些值在每个请求上都会被读取（例如注册开关），
// 走数据库会拖慢热路径。写入时同步刷新缓存。
type SettingStore struct {
	db     *gorm.DB
	cfg    *config.Config
	encKey string

	mu   sync.RWMutex
	vals map[SettingKey]string
}

// NewSettingStore 构造配置存储并完成首次加载。
func NewSettingStore(db *gorm.DB, cfg *config.Config) *SettingStore {
	s := &SettingStore{
		db:     db,
		cfg:    cfg,
		encKey: cfg.APIKeyEncKey,
		vals:   make(map[SettingKey]string, len(settingSpecs)),
	}
	if err := s.Reload(); err != nil {
		// 加载失败不阻断启动：回落到全部默认值，服务仍可用。
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
	}
}

// Reload 从数据库重新载入全部配置。
func (s *SettingStore) Reload() error {
	rows := make([]model.Setting, 0, len(settingSpecs))
	if err := s.db.Find(&rows).Error; err != nil {
		return err
	}
	stored := make(map[string]string, len(rows))
	for _, r := range rows {
		stored[r.Key] = r.Value
	}

	vals := make(map[SettingKey]string, len(settingSpecs))
	for _, spec := range settingSpecs {
		raw, ok := stored[string(spec.Key)]
		if !ok {
			vals[spec.Key] = spec.Default(s.cfg)
			continue
		}
		if spec.Secret {
			plain, err := auth.DecryptAPIKey(s.encKey, raw)
			if err != nil {
				// 密钥轮换或密文损坏时回落默认值，而不是让整站起不来。
				log.Printf("[setting] 解密 %s 失败，已回落默认值: %v", spec.Key, err)
				vals[spec.Key] = spec.Default(s.cfg)
				continue
			}
			vals[spec.Key] = plain
			continue
		}
		vals[spec.Key] = raw
	}

	s.mu.Lock()
	s.vals = vals
	s.mu.Unlock()
	return nil
}

// Get 读取字符串配置。
func (s *SettingStore) Get(k SettingKey) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vals[k]
}

// Bool 读取布尔配置。仅 "true"/"1"/"yes"/"on" 视为真。
func (s *SettingStore) Bool(k SettingKey) bool {
	switch strings.ToLower(strings.TrimSpace(s.Get(k))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// Int 读取整数配置，解析失败返回 0。
func (s *SettingStore) Int(k SettingKey) int {
	n, err := strconv.Atoi(strings.TrimSpace(s.Get(k)))
	if err != nil {
		return 0
	}
	return n
}

// SetMany 批量更新配置。只接受白名单内的键。
//
// 敏感字段提交 SecretMask 时表示不修改，避免前端把明文密钥回传。
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
		if spec.Secret && v == SecretMask {
			continue
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
	return s.Reload()
}

// AllForAdmin 返回给管理端的配置快照：敏感字段以占位符代替，绝不回传明文。
func (s *SettingStore) AllForAdmin() map[string]string {
	out := make(map[string]string, len(settingSpecs))
	for _, spec := range settingSpecs {
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

// UpdateSettings 校验后写入运行期配置。
//
// 校验基于「当前值 + 本次提交」的合并视图，因此可以跨字段判断
// （例如：只提交了开关、SMTP 参数沿用旧值时也能正确判断参数是否齐全）。
func (s *Services) UpdateSettings(in map[SettingKey]string) error {
	view := func(k SettingKey) string {
		if v, ok := in[k]; ok && v != SecretMask {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(s.Settings.Get(k))
	}
	truthy := func(k SettingKey) bool {
		switch strings.ToLower(view(k)) {
		case "true", "1", "yes", "on":
			return true
		}
		return false
	}

	// ---- 邮件 ----
	if truthy(KeySMTPEnabled) {
		host := view(KeySMTPHost)
		if host == "" {
			return fmt.Errorf("%w: 启用邮件前请填写 SMTP 服务器地址", ErrInvalidParam)
		}
		if view(KeySMTPUser) == "" || view(KeySMTPPassword) == "" {
			return fmt.Errorf("%w: 启用邮件前请填写 SMTP 账号与授权码", ErrInvalidParam)
		}
		switch strings.ToLower(view(KeySMTPTLS)) {
		case "ssl", "starttls", "none":
		default:
			return fmt.Errorf("%w: 邮件加密方式仅支持 ssl / starttls / none", ErrInvalidParam)
		}
		if s.Cfg.IsProd() && strings.EqualFold(view(KeySMTPTLS), "none") {
			return fmt.Errorf("%w: 生产环境禁止使用明文 SMTP", ErrInvalidParam)
		}
		port, err := strconv.Atoi(view(KeySMTPPort))
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("%w: SMTP 端口不合法", ErrInvalidParam)
		}
	}

	// ---- 支付 ----
	if truthy(KeyPaymentEnabled) {
		switch strings.ToLower(view(KeyPaymentProvider)) {
		case "easypay", "alipay", "wechat", "stripe":
		default:
			return fmt.Errorf("%w: 支付渠道仅支持 easypay / alipay / wechat / stripe", ErrInvalidParam)
		}
		if view(KeyPaymentAppID) == "" || view(KeyPaymentSecret) == "" {
			return fmt.Errorf("%w: 启用支付前请填写商户号与密钥", ErrInvalidParam)
		}
		if !strings.HasPrefix(view(KeyPaymentNotifyURL), "http") {
			return fmt.Errorf("%w: 支付回调地址必须是完整的 http(s) 地址", ErrInvalidParam)
		}
	}

	// ---- 端口 ----
	if ports := ParsePortList(view(KeyFirewallProtected)); len(ports) == 0 {
		return fmt.Errorf("%w: 保护端口列表不能为空，否则面板可能把自己锁在门外", ErrInvalidParam)
	}
	// 保护端口必须覆盖面板自身的监听端口，这是最后一道保险。
	if _, panelPort, err := splitHostPortLoose(s.Cfg.UserAddr); err == nil && panelPort != "" {
		if p, err := strconv.Atoi(panelPort); err == nil {
			if !ParsePortList(view(KeyFirewallProtected))[p] {
				return fmt.Errorf("%w: 保护端口必须包含控制面自身端口 %d", ErrInvalidParam, p)
			}
		}
	}

	// ---- 注册 ----
	if n, err := strconv.Atoi(view(KeyRegisterMaxPerIP)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单 IP 每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyRegisterMaxPerDomain)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单域名每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}

	allowDomains := ParseDomainList(view(KeyRegisterAllowDomains))
	blockDomains := ParseDomainList(view(KeyRegisterBlockDomains))
	for d := range allowDomains {
		if blockDomains[d] {
			return fmt.Errorf("%w: 域名 %s 同时出现在白名单与黑名单中，行为不可预期", ErrInvalidParam, d)
		}
	}
	if truthy(KeyRegisterWhitelistOnly) && len(allowDomains) == 0 {
		return fmt.Errorf("%w: 选择「仅允许白名单域名注册」时必须先填写白名单", ErrInvalidParam)
	}

	// ---- 接口限流 ----
	if n, err := strconv.Atoi(view(KeyAPIRatePerMinute)); err != nil || n < 1 || n > 100000 {
		return fmt.Errorf("%w: 接口每分钟请求上限需为 1-100000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyAPIRateBurst)); err != nil || n < 1 || n > 10000 {
		return fmt.Errorf("%w: 接口突发容量需为 1-10000 的整数", ErrInvalidParam)
	}

	return s.Settings.SetMany(in)
}

// ParsePortList 解析 "22,80,443,10000-10100" 形式的端口列表。
//
// 同时支持单个端口与闭区间，非法片段会被忽略而不是让整次调用失败——
// 这是运营配置，容忍个别笔误比直接报错更实用。
func ParsePortList(s string) map[int]bool {
	out := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start <= 0 || end < start || end > 65535 {
				continue
			}
			// 区间过大时截断，避免有人填 1-65535 把内存吃光。
			if end-start > 4096 {
				end = start + 4096
			}
			for p := start; p <= end; p++ {
				out[p] = true
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
			out[p] = true
		}
	}
	return out
}

// ParseDomainList 解析逗号分隔的域名列表，统一转小写并去掉 @ 前缀。
//
// 与 ParsePortList 一样采取宽容策略：忽略空项与格式明显错误的项，
// 不让一个笔误导致整份配置无法保存。
func ParseDomainList(s string) map[string]bool {
	out := make(map[string]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "@")))
		if part == "" || strings.ContainsAny(part, " \t\r\n/\\") {
			continue
		}
		// 只接受形如 a.b 的域名，避免把 IP 或路径写进来。
		if !strings.Contains(part, ".") {
			continue
		}
		out[part] = true
	}
	return out
}

// DomainInList 判断邮箱域名是否命中列表（含子域）。
func DomainInList(domain string, list map[string]bool) bool {
	if domain == "" || len(list) == 0 {
		return false
	}
	domain = strings.ToLower(domain)
	for d := range list {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// defaultTerms 是注册页默认展示的条款与禁止滥用说明。
var defaultTerms = func(*config.Config) string {
	return strings.Join([]string{
		"一、服务说明",
		"本平台提供内网穿透转发服务，仅用于合法的个人或企业自有系统访问。",
		"",
		"二、禁止行为",
		"1. 禁止用于任何违法违规用途，包括但不限于网络攻击、扫描探测、钓鱼、诈骗、传播违法信息；",
		"2. 禁止开放以下端口：25、110、143、465、587（邮件）、137-139、445（SMB）、3389（远程桌面）、",
		"   以及任何用于批量发送垃圾邮件或对外发起攻击的端口；",
		"3. 禁止利用本服务进行端口扫描、爆破、DDoS 攻击或作为跳板；",
		"4. 禁止传播恶意软件、挖矿程序或搭建任何形式的非法中继；",
		"5. 禁止转售、共享账号或超出授权范围使用。",
		"",
		"三、违规处置",
		"一经发现违规行为，平台有权立即停止服务、封禁账号、保留相关日志并配合有关部门调查。",
		"因违规行为导致的法律责任由使用者自行承担。",
		"",
		"四、其他",
		"平台会记录必要的连接与操作日志用于安全审计，日志保留不少于 6 个月。",
		"继续注册即表示你已阅读并同意上述条款。",
	}, "\n")
}

// splitHostPortLoose 宽松地拆出监听地址中的端口，用于生成默认的保护端口列表。
func splitHostPortLoose(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", errors.New("no port")
	}
	return addr[:i], addr[i+1:], nil
}
