package service

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
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
	//
	// 面板自身**不执行**任何防火墙写操作：它不含 iptables 调用，
	// 也不持有 NET_ADMIN。所有写请求转发给宿主机上的 lt-fw helper，
	// 由后者在受控条件下执行。
	//
	// 因此这里没有「后端选择」——那是 helper 自己的启动参数，
	// 因为只有它才需要知道本机跑的是 iptables 还是 firewalld。
	KeyPortReserved      SettingKey = "port.reserved"
	KeyFirewallEnabled   SettingKey = "firewall.enabled"
	KeyFirewallAutoOpen  SettingKey = "firewall.auto_open"
	KeyFirewallProtected SettingKey = "firewall.protected_ports"
	// 宿主机 helper 的回环地址与访问令牌
	KeyFirewallHelperAddr  SettingKey = "firewall.helper_addr"
	KeyFirewallHelperToken SettingKey = "firewall.helper_token"

	// ---- 站点 ----
	KeySiteName         SettingKey = "site.name"
	KeySiteAnnouncement SettingKey = "site.announcement"
	KeySiteICP          SettingKey = "site.icp"
	// KeySiteClientDownloadURL 是客户端下载地址。
	//
	// 填写后控制台的「客户端下载」页会直接引导用户去该地址（通常是
	// GitHub Releases），而不是列出服务器本地目录里的文件。
	// 这样做的好处是客户端不再需要人工搬运到服务器、也不会因为
	// 服务器磁盘被大文件占满而出问题；留空则回退到本地目录分发。
	KeySiteClientDownloadURL SettingKey = "site.client_download_url"

	// ---- 域名与证书 ----
	//
	// 这一组决定 Caddy 与 frps 的域名、证书与入口路由。
	//
	// 与其它运行期配置最大的不同：**只写数据库是不生效的**。Caddyfile 与
	// frps.toml 在宿主机上，改完必须重新渲染并重建容器，因此保存之后还有一步
	// 「下发」——由宿主机上的 lt-config helper 完成（见 cmd/lt-config）。
	// helper 的地址与令牌也就成了这一组配置的一部分，形制与防火墙 helper 一致。
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

	// ---- 已生效的域名配置（系统维护，面板不可写）----
	//
	// 上面那一组是**期望值**：管理员点了「保存」就写库了，但 Caddy 与 frps
	// 未必已经按它重建。而运行期的事（放行哪个域名的子域、拼出什么访问地址、
	// 有没有 HTTPS 隧道入口）只能按**已经生效**的那一份算：
	//
	//	只保存未下发 → 按新域名生成地址、放行新域名隧道，而实际在跑的是旧配置，
	//	               用户拿到一个打不开的地址，且没有任何地方提示原因；
	//	下发失败       → 同上，而且失败原因只在当次响应里，刷新页面就没了。
	//
	// 所以把「已应用」独立记一份，只有 helper 真的重建了容器才更新它，
	// 界面上把两者的差异显示成「待下发」。
	//
	// 「有没有成功下发过」的判据是**这一行存不存在**，而不是值是否为空：
	// 空值本身是有含义的——一次成功的下发可以把隧道关掉（期望值与已生效值
	// 都为空，两者一致，因此不该显示「待下发」）。升级路径也据此不猜：
	// 见 hasRow 附近那段说明。
	KeyDomainAppliedPanel  SettingKey = "domain.applied_panel"
	KeyDomainAppliedTunnel SettingKey = "domain.applied_tunnel"
	KeyDomainAppliedMode   SettingKey = "domain.applied_https_mode"

	// KeyDomainAppliedDigest 是「已下发那一份配置」的摘要。
	//
	// 前三项只覆盖决定**运行期行为**的输入（按哪个域名放行、按什么模式拼地址），
	// 但下发的输入不止这些：DNS 服务商、DNS 参数、凭据与 ACME 邮箱同样会改变
	// 渲染出的 Caddyfile 与 Caddy 的运行配置。只比较前三项的话，单独保存这些
	// 字段时页面会显示「与期望一致」，而磁盘上跑的还是旧配置——正是这一页要
	// 防的那件事。
	//
	// 存摘要而不是逐项存明文：凭据是密钥，复制一份到设置表等于多一处泄漏面。
	// 摘要只用于判等，不参与渲染。
	KeyDomainAppliedDigest SettingKey = "domain.applied_digest"
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
	// Internal 标记「只由服务内部写入」的项：面板既不能通过设置接口改它，
	// 管理端也读不到它。
	//
	// 用它而不是直接把这类项排除在白名单外：它们需要参与内存缓存
	// （运行期要高频读取），而缓存是按 settingSpecs 建的。
	Internal bool
	// SingleLine 表示这个值会被拼成配置文件里的一行（.env 的 key=value），
	// 因此不允许出现 CR、LF 或其他控制字符。
	//
	// 只在真正拼行的字段上打开：注册须知这类多行文本不在其列。
	SingleLine bool
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
	{Key: KeyFirewallAutoOpen, Default: func(*config.Config) string { return "true" }},
	{Key: KeyFirewallHelperAddr, Default: func(*config.Config) string { return "http://127.0.0.1:7849" }},
	{Key: KeyFirewallHelperToken, Secret: true, Default: func(*config.Config) string { return "" }},
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
	{Key: KeySiteClientDownloadURL, Default: func(*config.Config) string { return "" }},

	// 域名与证书。
	//
	// 默认值全部来自环境变量：这样「手工部署时在 .env 里填的域名」会
	// 自动成为界面上的初始值，第一次进后台就看到当前实际生效的配置，
	// 而不是一片空白。
	//
	// 这一组全部是 SingleLine：它们要么被拼成 .env 的 key=value 行交给 helper
	// 写盘，要么被拼进 HTTP 请求头（helper 地址与令牌）。一个换行就能往 .env
	// 里追加额外的配置行，把「面板无权覆盖某些变量」这条边界整个绕开。
	{Key: KeyDomainPanel, SingleLine: true, Default: func(c *config.Config) string { return normalizeDomainValue(c.UserPublicURL) }},
	{Key: KeyDomainTunnel, SingleLine: true, Default: func(c *config.Config) string { return normalizeDomainValue(c.TunnelDomain) }},
	{Key: KeyDomainACMEEmail, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSProvider, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSCredential, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainDNSArgs, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainHTTPSMode, SingleLine: true, Default: func(c *config.Config) string {
		// 初始值跟随 .env 里的 LT_HTTPS_TUNNEL_MODE：手工部署时怎么配的，
		// 后台第一次打开就显示什么，而不是一律显示默认值。
		if strings.EqualFold(strings.TrimSpace(c.HTTPSProxyMode), tlscfg.HTTPSModeE2E) {
			return tlscfg.HTTPSModeE2E
		}
		return tlscfg.HTTPSModeEdge
	}},
	{Key: KeyDomainExpectedIP, SingleLine: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainHelperAddr, SingleLine: true, Default: func(*config.Config) string { return "http://127.0.0.1:7850" }},
	{Key: KeyDomainHelperToken, Secret: true, SingleLine: true, Default: func(*config.Config) string { return "" }},

	// 已生效的域名配置。
	//
	// 默认值刻意留空而不是取环境变量：**没有这一行**才表示「还没有任何一次
	// 成功下发」，此时运行期回落到 .env（那才是实际在跑的配置）。若默认成
	// 期望值，「只保存未下发」就会被当成效已生效——正是这一组字段要解决的问题。
	//
	// 注意「有行且为空」是第三种状态，不是「没下发过」：它是隧道的明确关闭。
	{Key: KeyDomainAppliedPanel, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedTunnel, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedMode, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyDomainAppliedDigest, Internal: true, Default: func(*config.Config) string { return "" }},
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
	// present 记录每个键在数据库里**有没有行**，与它的值是否为空无关。
	//
	// 为什么要单独记：这些配置的默认值取自 .env，因此「值恰好等于默认值」与
	// 「管理员显式配成了这个值」在 vals 里长得一模一样。而隧道根域名必须区分
	// 这两种情况：
	//	没有行     → 从未配置过，继续以 .env 为准；
	//	有行且为空 → 管理员明确关闭了 HTTP/HTTPS 隧道。
	// 只看值的话，「清空后保存」会被静默当成「没配过」而回落到 .env——关闭
	// 动作成了空操作，而 Caddyfile 里的泛域名站点块也不会被剪掉。
	//
	// 放内存里而不是每次查库：用它的都是热路径（每个 HTTP/HTTPS 隧道请求都要
	// 按隧道根域名判权），一次 count 查询就把 SettingStore 存在的意义抵消了。
	present map[SettingKey]bool
}

// NewSettingStore 构造配置存储并完成首次加载。
func NewSettingStore(db *gorm.DB, cfg *config.Config) *SettingStore {
	s := &SettingStore{
		db:      db,
		cfg:     cfg,
		encKey:  cfg.APIKeyEncKey,
		vals:    make(map[SettingKey]string, len(settingSpecs)),
		present: make(map[SettingKey]bool, len(settingSpecs)),
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
		// 回落默认值意味着「这一份不是从库里读出来的」，因此视为没有行。
		s.present[spec.Key] = false
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
	present := make(map[SettingKey]bool, len(settingSpecs))
	for _, spec := range settingSpecs {
		raw, ok := stored[string(spec.Key)]
		if !ok {
			// 库里没有这一行：回落到 .env 派生的默认值，并记住「没有行」。
			vals[spec.Key] = spec.Default(s.cfg)
			continue
		}
		if spec.Secret {
			plain, err := auth.DecryptAPIKey(s.encKey, raw)
			if err != nil {
				// 密钥轮换或密文损坏时回落默认值，而不是让整站起不来。
				// 未采用库里的值，因此同样算「没有行」。
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
		if spec.Internal {
			// 管理端改不了「已生效」这一组：它只应该由下发流程按实际结果写入。
			// 允许手工改的话，界面可以显示「已生效」而宿主机上什么都没做。
			return fmt.Errorf("%w: %s 由系统维护，不能手工修改", ErrInvalidParam, k)
		}
		if spec.Secret && v == SecretMask {
			continue
		}
		// 会被拼成配置文件一行的字段，值里不能有换行或控制字符。
		//
		// 拒绝而不是过滤：这些值由 helper 拼进 .env 的 key=value，多一个换行
		// 就等于多一整行——「面板只能改这一小块」的边界可以被这样绕开。
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

// SetInternal 写入系统维护项（Internal 标记的那些值）并刷新缓存。
//
// 与 SetMany 分开，是为了让调用方一眼看出「这不是管理员改的配置」：
// 它只接受 Internal 项，值一律明文（这一组存的是域名与模式，不是密钥）。
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
	return s.Reload()
}

// hasRow 判断某个键在数据库里是否有记录（与它的值是否为空无关）。
//
// 结果取自内存快照（见 SettingStore.present）：每次写入都会重建它，因此刚
// SetMany / SetInternal 写下的行不会漏。
func (s *SettingStore) hasRow(k SettingKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.present[k]
}

// 这里刻意**没有**「升级时把期望值补成已生效」的对齐逻辑。
//
// 老版本里运行期是按库中的期望值算的，因此存在一种诱惑：升级后把期望值直接
// 记为已生效，省掉管理员的一次下发。但那只是把「不确定」伪装成「确定」——
// 那份期望值到底有没有真的下发过（helper 是否成功重建过 caddy 与 frps），
// 面板无从得知。猜错的代价是流量走在与界面不符的配置上，而猜对只省一次点击。
//
// 所以这一组保持为空，运行期以 .env 为准（那是唯一被证实正在跑的配置），
// 界面按「期望 ≠ 已生效」显示「待下发」，由管理员点一次下发来收敛——
// 那是唯一能确定答案的操作。

// AllForAdmin 返回给管理端的配置快照：敏感字段以占位符代替，绝不回传明文。
//
// Internal 项不返回：它们是下发结果，不是可编辑的配置项，出现在页面上只会
// 让管理员以为可以改。
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

// UpdateSettings 校验后写入运行期配置。
//
// 校验基于「当前值 + 本次提交」的合并视图，因此可以跨字段判断
// （例如：只提交了开关、SMTP 参数沿用旧值时也能正确判断参数是否齐全）。
func (s *Services) UpdateSettings(in map[SettingKey]string) error {
	// 本次提交改了「域名与证书」这一组时，与下发流程互斥（domainMu）：
	// 下发是逐个 key 读设置再渲染，读到一半插进一次保存，会把
	// 「从未作为整体保存过」的组合原样下发并记为已生效。
	//
	// 只在这一组**确实被改**时才取锁：下发可能持续数分钟，
	// 不能让改个公告的普通保存排在它后面。
	if touchesDomainSettings(in) {
		s.domainMu.Lock()
		defer s.domainMu.Unlock()
	}

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

	// ---- 防火墙 ----
	//
	// 启用前必须配好 helper。不校验的话，表现会是「开关打开了但没有任何
	// 效果」——管理员只能靠翻容器日志才知道 helper 没配。
	if truthy(KeyFirewallEnabled) {
		addr := view(KeyFirewallHelperAddr)
		if !strings.HasPrefix(addr, "http") {
			return fmt.Errorf("%w: 启用防火墙前请填写 helper 地址（形如 http://127.0.0.1:7849）", ErrInvalidParam)
		}
		token := view(KeyFirewallHelperToken)
		if len(token) < 16 {
			return fmt.Errorf("%w: helper 访问令牌至少 16 个字符，否则本机任意进程都能调用它改防火墙", ErrInvalidParam)
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

	// ---- 域名与证书 ----
	if err := validateDomainSettings(view, s.Settings.Get); err != nil {
		return err
	}

	// 记下改动前的防火墙开关：如果这次把它打开了，要立刻唤醒协调器，
	// 让它马上做一次规则对齐并开始重试待办，而不是等下一个轮询周期。
	firewallWasOn := s.Settings.Bool(KeyFirewallEnabled)

	if err := s.Settings.SetMany(in); err != nil {
		return err
	}

	if _, changed := in[KeyFirewallEnabled]; changed && !firewallWasOn && s.Settings.Bool(KeyFirewallEnabled) {
		s.KickFirewall()
	}
	return nil
}

// validateDomainSettings 校验「域名与证书」这一组。
//
// 只做面板自己就能判定的检查（域名格式、字段之间的依赖关系）；「这份配置
// Caddy 到底能不能加载」必须在宿主机上用**目标镜像**验证，那是 helper 的
// 职责（见 cmd/lt-config 的 validateCaddy）。
//
// 校验范围的取舍：域名本来就为空时直接放过。否则任何一次「改 SMTP 端口」
// 的保存都会因为「面板域名为空」而失败——把一个功能的未配置状态
// 扩散成整个设置页不可用。
func validateDomainSettings(view, current func(SettingKey) string) error {
	panel := normalizeDomainValue(view(KeyDomainPanel))
	if panel == "" {
		// 「本来就是空的」与「被清空了」必须分开处理。
		//
		// 前者是「域名还没配」的部署（开发环境、刚拉起还没填 .env），
		// 此时把整个设置页的保存一起堵死，等于让一个功能的未配置状态
		// 变成全站不可用；后者才是真正需要拦下的操作——Caddy 没有域名
		// 就签不出证书，找回密码的链接也无从拼起。
		if current(KeyDomainPanel) != "" {
			return fmt.Errorf("%w: 面板域名不能为空：Caddy 需要它签发证书，找回密码邮件也要用它拼链接", ErrInvalidParam)
		}
		return nil
	}
	if err := checkDomain(panel); err != nil {
		return fmt.Errorf("%w: 面板域名不合法（%s）", ErrInvalidParam, err.Error())
	}

	tunnel := normalizeDomainValue(view(KeyDomainTunnel))
	if tunnel != "" {
		if err := checkDomain(tunnel); err != nil {
			return fmt.Errorf("%w: 隧道根域名不合法（%s）", ErrInvalidParam, err.Error())
		}
		if tunnel == panel {
			return fmt.Errorf("%w: 隧道根域名不能与面板域名相同：同一个域名既要由 Caddy 提供控制台、又要按子域转发隧道，"+
				"证书配额与排查都会立刻变成灾难", ErrInvalidParam)
		}
		// 泛域名证书只能走 DNS Challenge：没有 dns 指令就签不出证书，
		// 缺的不是「一项配置」，而是整个 HTTP/HTTPS 隧道入口。
		if strings.TrimSpace(view(KeyDomainDNSProvider)) == "" {
			return fmt.Errorf("%w: 已填写隧道根域名但未选择 DNS 服务商：泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证", ErrInvalidParam)
		}
	}

	switch strings.ToLower(strings.TrimSpace(view(KeyDomainHTTPSMode))) {
	case "", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E:
	default:
		return fmt.Errorf("%w: HTTPS 隧道模式只能是 %s（证书留在 Caddy）或 %s（证书留在本地网站）",
			ErrInvalidParam, tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E)
	}

	if ip := strings.TrimSpace(view(KeyDomainExpectedIP)); ip != "" && net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: DNS 检查的期望地址不是合法 IP", ErrInvalidParam)
	}

	if addr := strings.TrimSpace(view(KeyDomainHelperAddr)); addr != "" && !strings.HasPrefix(addr, "http") {
		return fmt.Errorf("%w: 配置服务地址需形如 http://127.0.0.1:7850", ErrInvalidParam)
	}
	if token := view(KeyDomainHelperToken); token != "" && len(token) < 16 {
		return fmt.Errorf("%w: 配置服务访问令牌至少 16 个字符，否则本机任意进程都能让它重写 TLS 配置并重启容器", ErrInvalidParam)
	}
	return nil
}

// domainSettingKeys 是「域名与证书」里参与渲染下发的键，与 domainVars 同源。
//
// 以此判断一次保存要不要与下发互斥。helper 地址与令牌不在其中：
// 它们决定「找哪个 helper」，不进 Caddyfile / frps.toml，也不进已生效的
// 摘要——保存它们与一次进行中的下发交错，不会产生「从未保存过的组合」。
var domainSettingKeys = []SettingKey{
	KeyDomainPanel,
	KeyDomainTunnel,
	KeyDomainACMEEmail,
	KeyDomainDNSProvider,
	KeyDomainDNSArgs,
	KeyDomainDNSCredential,
	KeyDomainHTTPSMode,
}

// touchesDomainSettings 报告一次设置提交是否改动了「域名与证书」的渲染输入。
func touchesDomainSettings(in map[SettingKey]string) bool {
	for _, k := range domainSettingKeys {
		if _, ok := in[k]; ok {
			return true
		}
	}
	return false
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
