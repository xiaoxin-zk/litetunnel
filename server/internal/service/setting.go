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
	// KeyRegisterNonWhitelistQuota 是白名单模式下「白名单外域名」的放量口径。
	//
	// 0（默认）= 直接拒绝；N = 每个主域最多注册 N 个账号（累计，不按天重置）。
	// 白名单为空时该值无效果——没有白名单就谈不上「白名单外」，
	// 这一点与 sub2api 的「白名单非空时才生效」保持一致。
	KeyRegisterNonWhitelistQuota SettingKey = "register.non_whitelist_quota"

	// ---- 登录防护 ----
	//
	// KeyLoginCaptchaAfter 是「同一账号连续失败几次后要求验证码」的阈值。
	//
	// 计数落在数据库（lt_login_fail_counters，见 loginfail_db.go），因此
	// **多实例共用一个库时阈值仍然成立**。这一点很关键：账号级验证码是
	// 分布式爆破的唯一克星（硬锁按「账号 + IP」计数，分布式来源每个 IP
	// 各有一份额度），若计数只在进程内，N 个实例就等于 N 倍额度，而且
	// 退化时没有任何报错或指标。
	//
	// 注意同层的硬锁（middleware.LoginGuard，账号 + IP 的锁定）仍是进程内的：
	// 多实例部署时锁定状态不共享，要么在网关层做会话粘滞，要么接受
	// 「硬锁按实例计、账号级验证码兜底」这一组合。
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
	KeyFirewallAutoClose SettingKey = "firewall.auto_close"
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

	// ---- 接入信息（下发给客户端与控制台）----
	//
	// 决定用户端「客户端下载 → 接入信息」显示的服务器地址，以及下载到的
	// frpc 配置里的 serverAddr 与 tls.serverName。
	//
	// 默认值回落 .env 的 LT_GATEWAY_HOST / LT_GATEWAY_PORT，老部署升级后行为
	// 不变；但改它不再需要登录服务器编辑 .env 再重启面板。
	KeyGatewayHost SettingKey = "gateway.host"
	KeyGatewayPort SettingKey = "gateway.port"

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

	// KeyTrafficBaselineReady 是「流量采样基线已建立」的一次性迁移标记。
	//
	// TrafficBaseline 表是后续版本才加入的：升级旧库时这张表是空的，
	// 而表的「空」有两种含义——「首次迁移，还没写过任何基线」与
	// 「当天还没有采集轮次写入」。不区分的话，升级后的第一轮采集会把
	// frps 的当天累计值从零起算整个计入，而那部分流量旧版本已经计过：
	// 用户被重复扣费，甚至触发超额封禁。
	//
	// 缺失 = 首次迁移：第一轮采集只写基线、不计增量，写成功后置位
	// （见 loadTrafficBaseline 与 collectTraffic）。之后这张表再怎么空
	// 都是正常状态（frps 重启归零、当天没有代理），恢复正常计增量。
	KeyTrafficBaselineReady SettingKey = "traffic.baseline_ready"

	// KeyTrafficResetMarkReady 是「清零代次标记已初始化」的一次性迁移标记。
	//
	// 与基线标记必须分开：基线就绪只说明「有基线可以相减」，不能证明
	// 「基线对应的清零代次已经记下」。升级前的旧库有基线、没有标记表，
	// 若此时控制面停机期间发生过清零，升级后首轮会拿「没有记录」当成
	// 「代次没变」，把清零前的流量重新计入——用量虚高，甚至触发超额。
	//
	// 缺失 = 首次启用：第一轮只写基线、不计增量（与基线迁移同样的保守策略），
	// 顺带把当轮采样到的代次写进标记表，然后置位。
	KeyTrafficResetMarkReady SettingKey = "traffic.reset_mark_ready"
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
	{Key: KeyRegisterNonWhitelistQuota, Default: func(*config.Config) string { return "0" }},

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
	{Key: KeyFirewallAutoClose, Default: func(*config.Config) string { return "true" }},
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

	// 接入信息：默认回落 .env，升级后行为不变
	{Key: KeyGatewayHost, SingleLine: true, Default: func(c *config.Config) string { return c.GatewayHost }},
	{Key: KeyGatewayPort, Default: func(c *config.Config) string {
		// 零值兜底 7001：与 config.Load 的默认一致。少了这一层，测试用的空
		// Config 会让默认值变成 "0"，连「保存任意设置」都会被端口校验拦下。
		p := c.GatewayPort
		if p <= 0 {
			p = 7001
		}
		return strconv.Itoa(p)
	}},

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

	// 流量采集迁移标记：见 KeyTrafficBaselineReady 与 KeyTrafficResetMarkReady。
	{Key: KeyTrafficBaselineReady, Internal: true, Default: func(*config.Config) string { return "" }},
	{Key: KeyTrafficResetMarkReady, Internal: true, Default: func(*config.Config) string { return "" }},
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

	// raw 是上一次从库里读到的**原始**行（含密文），用于判断「别的实例有没有
	// 改过配置」（见 ReloadIfChanged）。
	//
	// 存原文而不是解析后的值：比较的目的是「这一份快照是否已经过时」，
	// 加密字段解出来是同一个明文就说明没变，但解密的成本与失败回落都
	// 不该掺进这个判断里。
	raw map[string]string

	// reloadMu 串行化「读库 → 应用」这一整段，写配置（SetMany / SetInternal）
	// 与周期刷新（ReloadIfChanged）共用它。
	//
	// 没有它时存在一个窗口：周期刷新先读到旧值，管理员随后写入并重载了新值，
	// 周期刷新最后才把手里那份旧快照应用上去——本实例的缓存短暂回退，
	// 要等下一个轮询周期才恢复。持有这把锁之后，「读」与「写 + 重载」不再
	// 交错：晚到的快照只可能来自更晚的读，不会覆盖更新的本地写入。
	//
	// 注意它只保护「缓存与库的同步顺序」，不是 mu 的替代：缓存本身的读写
	// 仍由 mu（RWMutex）保护，Get 等热路径不受这把锁影响。
	reloadMu sync.Mutex
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
	// 没有读到库里的行：清掉快照，下一次 ReloadIfChanged 一定判为「变了」
	// 并重新读一次——启动时读失败不再需要重启才能恢复。
	s.raw = nil
}

// Reload 从数据库重新载入全部配置。
func (s *SettingStore) Reload() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadLocked()
}

// reloadLocked 在**已持有 reloadMu** 的前提下读库并重建缓存。
//
// 写配置的路径也在锁内调用它：写入与随后的重载必须相对其他重载是原子的，
// 否则一次更早开始的刷新可能在本实例写完、重载完之后才把旧快照贴回来。
func (s *SettingStore) reloadLocked() error {
	stored, err := s.fetch()
	if err != nil {
		return err
	}
	s.apply(stored)
	return nil
}

// ReloadIfChanged 在库里的配置与本地快照不一致时重新载入，返回是否发生了更新。
//
// # 为什么需要它
//
// 配置缓存在内存里，而缓存只在**本实例**写配置之后刷新。多实例共用一个库时，
// 管理员在 A 上保存的保留端口、注册开关、配额规则，B 会一直按旧值运行——
// 例如 A 新增了保留端口，B 仍可能把那个端口分配出去，直到 B 重启。
//
// 判据取「整表原文是否一致」而不是 updated_at：这几十行的读取成本可以忽略，
// 而时间戳依赖每条写入路径都正确维护它，漏掉一处（原生 SQL、批量更新）
// 就会永远同步不过去。整表比较不依赖任何列语义。
func (s *SettingStore) ReloadIfChanged() (bool, error) {
	// 整段「读 → 比较 → 应用」都在 reloadMu 内：否则一份在管理员写入之前
	// 读到的旧快照，可能在写入并重载之后才被应用，缓存短暂回退到旧值。
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

// fetch 读出设置表的全部原始行。
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

// apply 用一份库里的原始行重建内存缓存。
func (s *SettingStore) apply(stored map[string]string) {
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
	s.raw = stored
	s.mu.Unlock()
}

// Get 读取字符串配置。
func (s *SettingStore) Get(k SettingKey) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vals[k]
}

// Snapshot 在一把读锁内取多个键的值与「是否存在」标记。
//
// 域名配置的校验、DNS 检查与下发各自会读 6~9 个键：逐个 Get 时，另一台
// 实例（或本进程的保存请求）可以在两次读取之间写入新值，导致一次检查
// 用着「旧域名 + 新凭据」这种从未存在过的组合。
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

	// 写入与随后的重载必须在同一把锁内完成（见 reloadMu）：否则一次更早
	// 开始、更晚结束的周期刷新会把旧快照贴回来，本实例缓存回退到写入前。
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
	// 与 SetMany 同样：写入与重载在同一把锁内，避免被更早的快照覆盖。
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

// hasRow 判断某个键在数据库里是否有记录（与它的值是否为空无关）。
//
// 结果取自内存快照（见 SettingStore.present）：每次写入都会重建它，因此刚
// SetMany / SetInternal 写下的行不会漏。
func (s *SettingStore) hasRow(k SettingKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.present[k]
}

// ReloadSettingsIfChanged 让运行期配置与其他实例的写入收敛。
//
// 由采集协程每个周期调用一次（默认 30 秒）。收敛延迟与采集周期一致，对
// 「保留端口」「注册开关」这类配置足够；真正的热路径仍然只读内存缓存。
//
// 必须在 domainMu 内重载：域名下发是「读一整组设置 → 渲染 → 校验 → 写盘 →
// 记录已生效」，全程持这把锁，但耗时可到几分钟。重载若插在它读取的中途，
// 下发方会拿到「新面板域名 + 旧隧道域名」这种从未在任何一次保存里存在过的
// 组合，并且那份组合随后被登记成「已生效」——界面显示一致，实际跑的是
// 一份谁也没要求过的配置。
//
// 用 TryLock 而不是 Lock：采集协程不能为一次可能持续几分钟的下发停下，
// 它还要记账与刷新准入。拿不到就跳过本轮，下一个周期再对齐；
// 收敛晚 30 秒没有任何影响。
func (s *Services) ReloadSettingsIfChanged() {
	if !s.domainMu.TryLock() {
		return
	}
	defer s.domainMu.Unlock()

	changed, err := s.Settings.ReloadIfChanged()
	if err != nil {
		// 数据库暂时不可用：保持现有缓存（旧值仍然可用），下一轮再试。
		// 不在这里打日志：采集与准入路径已经各自记过读库失败，重复只会刷屏。
		return
	}
	if changed {
		log.Printf("[setting] 检测到其他实例修改了运行期配置，已重新载入")
	}
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
