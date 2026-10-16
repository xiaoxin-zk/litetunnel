// Package config 负责集中加载运行期配置。
//
// 安全约定：
//  1. 所有与部署环境相关的值（公网 IP、域名、密钥）一律通过环境变量注入，
//     源码与默认值中不得出现任何真实地址或可用密钥。
//  2. 非生产环境缺失密钥时**随机生成**，绝不使用硬编码默认值：
//     否则源码公开后，任何以默认环境变量启动的实例都能被伪造令牌接管。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const placeholderPrefix = "CHANGE_ME"

// Version 是构建时注入的版本号，用于确认线上跑的是哪个版本。
//
// 通过 -ldflags 注入，例如：
//
//	go build -ldflags "-X github.com/xiaoxin-zk/litetunnel/server/internal/config.Version=v1.0.0"
//
// 未注入时保持 dev，便于区分本地构建产物。
var Version = "dev"

// Config 为控制面全部可配置项。
type Config struct {
	Env      string
	LogLevel string

	// 存储
	DBDriver string // sqlite | postgres
	DBDSN    string

	// 监听地址：单一入口，用户控制台与管理后台共用同一端口，
	// 通过路径前缀区分（管理后台挂在 AdminPath 下）。
	UserAddr      string
	UserPublicURL string

	// AdminPath 是管理后台的挂载路径。
	//
	// 刻意不使用 /admin 这类扫描器字典里的高频路径：管理后台虽然是
	// 公网可达的（安全由账号锁定 + 限流 + 双因素保证），但把入口藏在
	// 一个自定义路径下能挡掉绝大部分自动化探测流量。
	//
	// 前端采用哈希路由 + 相对资源路径，因此本值可随时修改而无需重新构建镜像。
	AdminPath string

	// AdminAllowCIDRs 可选的管理后台来源白名单。
	// 为空表示管理后台同样对公网开放（默认），此时安全性由
	// 账号锁定 + 限流 + 双因素认证共同保证。
	AdminAllowCIDRs []string

	// 双域密钥：用户令牌与管理令牌互不通用
	UserJWTSecret  string
	AdminJWTSecret string
	APIKeyEncKey   string

	BootstrapAdminUser     string
	BootstrapAdminPassword string

	// 隧道网关
	GatewayHost string
	GatewayPort int

	FrpsToken       string
	FrpsAPIAddr     string
	FrpsAPIUser     string
	FrpsAPIPassword string

	// FrpsPluginAllowCIDRs 是允许调用服务端插件回调的来源网段。
	// frp 的 HTTP 插件协议不支持自定义鉴权头，因此改用来源 IP 白名单，
	// 默认仅允许回环地址（frps 与本服务同机部署）。
	FrpsPluginAllowCIDRs []string

	PortRangeStart  int
	PortRangeEnd    int
	MaxPortsPerUser int

	TunnelDomain string

	// VhostHTTPSPort 是 frps 的 HTTPS 隧道入口端口（LT_VHOST_HTTPS_PORT，默认 8444）。
	//
	// 面板需要知道它，才能在客户端里显示 HTTPS 隧道的**真实**访问地址：
	// 端到端模式下那条隧道不在 443 上，地址必须带端口——只给一个裸域名的话，
	// 用户会拿到 Caddy 的证书并看到「证书不匹配」，然后以为是自己配错了。
	//
	// 值来自 .env：面板容器通过 env_file 读到整份 .env，与渲染 frps.toml
	// 用的是同一个来源，因此不存在「两份数据互相分叉」的问题。
	VhostHTTPSPort int

	// HTTPSProxyMode 是 HTTPS 隧道模式（LT_HTTPS_TUNNEL_MODE：edge / e2e）。
	//
	// 只作为管理端设置的**初始默认值**：运行期以数据库里的设置为准
	// （管理端改完由 helper 回写 .env，而面板容器不会重启，
	// 拿这里当运行期真相会让界面与实际配置长期不一致）。
	HTTPSProxyMode string

	// ClientDistDir 存放对外分发的客户端安装包目录，由控制台列出供下载。
	ClientDistDir string

	// 两个控制台的前端构建产物目录。目录不存在时服务以纯 API 模式运行（开发用）。
	UserWebDir  string
	AdminWebDir string

	// TrustedProxies 是允许其转发头生效的反向代理地址。
	// 默认为回环地址（反代与本服务同机），避免客户端伪造 X-Forwarded-For 绕过限流。
	TrustedProxies []string

	// SMTP 邮件发送配置。未配置时找回密码功能自动禁用，接口会明确返回提示。
	SMTP SMTPConfig

	TrafficPollInterval time.Duration

	UserJWTExpire  time.Duration
	AdminJWTExpire time.Duration

	// ---- 以下字段在 Load 时填充，供 main 输出启动提示 ----

	// GeneratedSecrets 记录本次启动随机生成的密钥名，值为空说明来自环境变量。
	GeneratedSecrets []string
	// EphemeralAdminPassword 仅在未提供初始管理员密码时生成，重启即失效。
	EphemeralAdminPassword bool
	// Warnings 收集非致命的配置风险提示。
	Warnings []string
}

// SMTPConfig 是邮件发送配置。
//
// 以 QQ 邮箱为例（国内服务器最常用的方案）：
//
//	LT_SMTP_HOST=smtp.qq.com
//	LT_SMTP_PORT=465
//	LT_SMTP_TLS=ssl
//	LT_SMTP_USER=你的QQ号@qq.com
//	LT_SMTP_PASS=在QQ邮箱设置里生成的「授权码」（不是登录密码）
//	LT_SMTP_FROM=LiteTunnel <你的QQ号@qq.com>
//
// 注意：国内服务器 25 端口普遍被封，请使用 465(SSL) 或 587(STARTTLS)。
type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	// From 是收件人看到的发件人。多数服务商要求它必须与 User 一致。
	From string
	// TLS 取值：ssl（隐式 TLS，465）、starttls（587）、none（明文，仅内网调试）。
	TLS string
	// SiteName 用于邮件标题与正文中的品牌名。
	SiteName string
}

// Enabled 表示邮件功能是否可用。
func (s SMTPConfig) Enabled() bool {
	return s.Host != "" && s.User != "" && s.Password != ""
}

// Load 从环境变量装载配置并做必要校验。
func Load() (*Config, error) {
	c := &Config{
		Env:      env("LT_ENV", "development"),
		LogLevel: env("LT_LOG_LEVEL", "info"),

		DBDriver: env("LT_DB_DRIVER", "sqlite"),
		DBDSN:    env("LT_DB_DSN", "./data/litetunnel.db"),

		UserAddr:        env("LT_USER_ADDR", "0.0.0.0:7848"),
		UserPublicURL:   strings.TrimRight(env("LT_USER_PUBLIC_URL", ""), "/"),
		AdminPath:       env("LT_ADMIN_PATH", "/lt-console"),
		AdminAllowCIDRs: splitCSV(env("LT_ADMIN_ALLOW_CIDR", "")),

		UserJWTSecret:  env("LT_USER_JWT_SECRET", ""),
		AdminJWTSecret: env("LT_ADMIN_JWT_SECRET", ""),
		APIKeyEncKey:   env("LT_APIKEY_ENC_KEY", ""),

		BootstrapAdminUser:     env("LT_BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapAdminPassword: env("LT_BOOTSTRAP_ADMIN_PASSWORD", ""),

		GatewayHost: env("LT_GATEWAY_HOST", ""),
		GatewayPort: envInt("LT_GATEWAY_PORT", 7001),

		FrpsToken:            env("LT_FRPS_TOKEN", ""),
		FrpsAPIAddr:          env("LT_FRPS_API_ADDR", "127.0.0.1:7500"),
		FrpsAPIUser:          env("LT_FRPS_API_USER", ""),
		FrpsAPIPassword:      env("LT_FRPS_API_PASSWORD", ""),
		FrpsPluginAllowCIDRs: splitCSV(env("LT_FRPS_PLUGIN_ALLOW_CIDR", "127.0.0.1/32,::1/128")),

		PortRangeStart:  envInt("LT_PORT_RANGE_START", 20000),
		PortRangeEnd:    envInt("LT_PORT_RANGE_END", 30000),
		MaxPortsPerUser: envInt("LT_MAX_PORTS_PER_USER", 10),

		TunnelDomain: strings.ToLower(strings.TrimSpace(env("LT_TUNNEL_DOMAIN", ""))),

		VhostHTTPSPort: envInt("LT_VHOST_HTTPS_PORT", 8444),
		HTTPSProxyMode: strings.ToLower(strings.TrimSpace(env("LT_HTTPS_TUNNEL_MODE", "edge"))),

		ClientDistDir: env("LT_CLIENT_DIST_DIR", "./data/clients"),
		UserWebDir:    env("LT_USER_WEB_DIR", "./web/user/dist"),
		AdminWebDir:   env("LT_ADMIN_WEB_DIR", "./web/admin/dist"),
		TrustedProxies: splitCSV(
			env("LT_TRUSTED_PROXIES", "127.0.0.1,::1"),
		),

		SMTP: SMTPConfig{
			Host:     env("LT_SMTP_HOST", ""),
			Port:     envInt("LT_SMTP_PORT", 465),
			User:     env("LT_SMTP_USER", ""),
			Password: env("LT_SMTP_PASS", ""),
			From:     env("LT_SMTP_FROM", ""),
			TLS:      strings.ToLower(env("LT_SMTP_TLS", "ssl")),
			SiteName: env("LT_SITE_NAME", "LiteTunnel"),
		},

		TrafficPollInterval: time.Duration(envInt("LT_TRAFFIC_POLL_INTERVAL", 30)) * time.Second,
		UserJWTExpire:       12 * time.Hour,
		AdminJWTExpire:      4 * time.Hour,
	}

	if err := c.fillDefaults(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// IsProd 返回是否生产环境。
func (c *Config) IsProd() bool { return c.Env == "production" }

// fillDefaults 为非生产环境补齐缺失项。
//
// 关键点：这里**不使用硬编码密钥**，而是每次启动随机生成。
// 否则源码公开后，任何用默认环境变量启动的实例都能被伪造令牌接管。
func (c *Config) fillDefaults() error {
	if c.IsProd() {
		return nil
	}

	gen := func(target *string, name string) error {
		if *target != "" {
			return nil
		}
		v, err := randomHex(32)
		if err != nil {
			return err
		}
		*target = v
		c.GeneratedSecrets = append(c.GeneratedSecrets, name)
		return nil
	}

	if err := gen(&c.UserJWTSecret, "LT_USER_JWT_SECRET"); err != nil {
		return err
	}
	if err := gen(&c.AdminJWTSecret, "LT_ADMIN_JWT_SECRET"); err != nil {
		return err
	}
	if err := gen(&c.APIKeyEncKey, "LT_APIKEY_ENC_KEY"); err != nil {
		return err
	}
	if c.BootstrapAdminPassword == "" {
		v, err := randomHex(12)
		if err != nil {
			return err
		}
		c.BootstrapAdminPassword = v
		c.EphemeralAdminPassword = true
	}
	if c.GatewayHost == "" {
		c.GatewayHost = "127.0.0.1"
	}
	if c.FrpsToken == "" {
		v, err := randomHex(32)
		if err != nil {
			return err
		}
		c.FrpsToken = v
		c.GeneratedSecrets = append(c.GeneratedSecrets, "LT_FRPS_TOKEN")
	}
	return nil
}

func (c *Config) validate() error {
	if c.DBDriver != "sqlite" && c.DBDriver != "postgres" {
		return fmt.Errorf("LT_DB_DRIVER 仅支持 sqlite 或 postgres，当前为 %q", c.DBDriver)
	}

	adminPath, err := normalizeAdminPath(c.AdminPath)
	if err != nil {
		return err
	}
	c.AdminPath = adminPath

	// 邮件配置校验：只校验「已配置」的情况，未配置时视为禁用该功能。
	if c.SMTP.Host != "" {
		switch c.SMTP.TLS {
		case "ssl", "starttls", "none":
		default:
			return fmt.Errorf("LT_SMTP_TLS 仅支持 ssl / starttls / none，当前为 %q", c.SMTP.TLS)
		}
		if c.SMTP.Port <= 0 || c.SMTP.Port > 65535 {
			return errors.New("LT_SMTP_PORT 配置非法")
		}
		if c.SMTP.User == "" || c.SMTP.Password == "" {
			return errors.New("已配置 LT_SMTP_HOST 但缺少 LT_SMTP_USER 或 LT_SMTP_PASS")
		}
		if c.SMTP.From == "" {
			// 未显式指定发件人时回落到认证账号，这是大多数服务商的要求。
			c.SMTP.From = c.SMTP.User
		}
		if c.IsProd() && c.SMTP.TLS == "none" {
			return errors.New("生产环境禁止使用明文 SMTP（LT_SMTP_TLS=none）")
		}
	}
	if c.PortRangeStart <= 0 || c.PortRangeEnd <= c.PortRangeStart {
		return errors.New("LT_PORT_RANGE_START/END 配置非法")
	}
	if c.PortRangeStart < 1024 {
		return errors.New("端口池起始端口不得低于 1024（禁止占用特权端口）")
	}

	// 转发头信任范围必须显式收窄，否则客户端可伪造来源 IP 绕过限流与白名单。
	for _, p := range c.TrustedProxies {
		if isTrustAll(p) {
			return fmt.Errorf("LT_TRUSTED_PROXIES 不允许配置 %q：那会让任意客户端伪造来源 IP", p)
		}
		// 还必须是合法的 IP 或 CIDR。
		//
		// 这一步不能省：gin 的 SetTrustedProxies 遇到非法值会解析失败并提前返回，
		// 而它内部的 trustedCIDRs 会保留构造函数写入的「信任所有」默认值。
		// 也就是说一个拼错的 CIDR（如 127.0.0.1/33）会让整条信任链失效，
		// 且失败是静默的。这里提前拦截，让问题在启动时暴露。
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			return fmt.Errorf("LT_TRUSTED_PROXIES 中的 %q 不是合法的 IP 或 CIDR", p)
		}
	}
	// 两份 CIDR 白名单都必须逐项可解析。
	//
	// 为什么要在启动时挡住，而不是留给运行期：解析失败的条目会被静默丢弃，
	// 而这两处的语义恰好都建立在「列表非空」上——
	//
	//	管理白名单：解析结果为空会被当成「不限制」，于是「填了白名单但每项
	//	            都拼错」不是谁都进不来，而是**公网谁都能进后台**；
	//	插件白名单：解析结果为空会让所有回调被拒，隧道全部无法上线，
	//	            而报错只是一个 403 日志，看不出是配置写错了。
	//
	// 两种后果都必须等到线上才暴露，代价与「启动失败」完全不成比例。
	if err := validateCIDRList("LT_ADMIN_ALLOW_CIDR", c.AdminAllowCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("LT_FRPS_PLUGIN_ALLOW_CIDR", c.FrpsPluginAllowCIDRs); err != nil {
		return err
	}

	if !c.IsProd() {
		// 非生产环境只做风险提示，不阻断启动，便于本地调试。
		if isPublicBind(c.UserAddr) {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("当前为非生产环境且监听在 %s，任何人都可能访问；请勿用于公网", c.UserAddr))
		}
		if c.UserPublicURL == "" {
			// 这里必须提示：找回密码的重置链接要用它，而运行时不会再从请求头
			// 推断（那会被 Host 投毒）。不提示的话，用户点了「忘记密码」之后
			// 什么都不会发生，管理员却不知道原因。
			c.Warnings = append(c.Warnings,
				"未配置 LT_USER_PUBLIC_URL，找回密码的邮件不会发出（重置链接无法生成）；本地调试请设为 http://localhost:<端口>")
		}
		return nil
	}

	// ---- 生产环境强制校验，避免带着占位符上线 ----
	var missing []string
	require := func(name, v string) {
		if v == "" || strings.HasPrefix(v, placeholderPrefix) {
			missing = append(missing, name)
		}
	}
	require("LT_USER_JWT_SECRET", c.UserJWTSecret)
	require("LT_ADMIN_JWT_SECRET", c.AdminJWTSecret)
	require("LT_APIKEY_ENC_KEY", c.APIKeyEncKey)
	require("LT_BOOTSTRAP_ADMIN_PASSWORD", c.BootstrapAdminPassword)
	require("LT_GATEWAY_HOST", c.GatewayHost)
	require("LT_FRPS_TOKEN", c.FrpsToken)
	require("LT_FRPS_API_PASSWORD", c.FrpsAPIPassword)
	// 对外地址必须显式配置：找回密码的重置链接要用它。
	//
	// 没有它就只能从请求的 Host / X-Forwarded-Proto 推断，而这两个头完全由
	// 请求方控制——攻击者往找回密码接口提交伪造的 Host，就能让发给用户的邮件
	// 里的链接指向他自己的域名，用户一点，重置令牌就落到他手里。
	// 因此生产环境必须配置，运行时也**绝不**再退回到请求头（见 userapi.ForgotPassword）。
	require("LT_USER_PUBLIC_URL", c.UserPublicURL)

	if len(missing) > 0 {
		return fmt.Errorf("生产环境缺少或仍为占位符的配置项: %s", strings.Join(missing, ", "))
	}
	if len(c.FrpsPluginAllowCIDRs) == 0 {
		return errors.New("生产环境必须显式配置 LT_FRPS_PLUGIN_ALLOW_CIDR")
	}
	if c.UserJWTSecret == c.AdminJWTSecret {
		return errors.New("用户域与管理域必须使用不同的 JWT 密钥")
	}
	if len(c.UserJWTSecret) < 24 || len(c.AdminJWTSecret) < 24 {
		return errors.New("JWT 密钥长度不得少于 24 个字符")
	}
	if len(c.APIKeyEncKey) != 32 && len(c.APIKeyEncKey) != 64 {
		return errors.New("LT_APIKEY_ENC_KEY 需为 32 或 64 个字符（AES-128/256 密钥）")
	}
	// 管理后台与用户控制台共用公网端口，安全依赖以下三件事，
	// 缺任何一件都会让公网暴露的后台变成可爆破目标，因此必须显式确认。
	if len(c.AdminAllowCIDRs) == 0 {
		c.Warnings = append(c.Warnings,
			"管理后台当前对公网开放（未配置 LT_ADMIN_ALLOW_CIDR）。"+
				"请务必启用管理员双因素认证，否则仅有密码一道防线")
	}
	return nil
}

// reservedPathPrefixes 是管理后台路径不得占用的前缀。
// 它们被接口、健康检查或静态资源使用，占用会导致路由冲突。
var reservedPathPrefixes = []string{"/api", "/healthz", "/assets", "/favicon"}

// normalizeAdminPath 规范化并校验管理后台挂载路径。
//
// 只接受单层路径（形如 /xxx），字符集限制为字母数字与 - _，
// 避免出现 /a/b 这类多段路径或包含点号的路径引发路由歧义与目录穿越联想。
func normalizeAdminPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("LT_ADMIN_PATH 不能为空")
	}
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return "", errors.New("LT_ADMIN_PATH 不能为根路径，否则会与用户控制台冲突")
	}
	if len(p) < 4 {
		return "", errors.New("LT_ADMIN_PATH 至少需要 3 个字符，过短容易被猜中")
	}
	if len(p) > 64 {
		return "", errors.New("LT_ADMIN_PATH 不得超过 64 个字符")
	}
	if strings.Contains(p[1:], "/") {
		return "", errors.New("LT_ADMIN_PATH 只支持单层路径，例如 /lt-console")
	}
	for _, r := range p[1:] {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return "", fmt.Errorf("LT_ADMIN_PATH 只允许字母、数字、- 与 _，当前为 %q", p)
		}
	}
	lower := strings.ToLower(p)
	for _, reserved := range reservedPathPrefixes {
		if lower == reserved || strings.HasPrefix(lower, reserved+"/") {
			return "", fmt.Errorf("LT_ADMIN_PATH 不能占用保留前缀 %s", reserved)
		}
	}
	return p, nil
}

// isPublicBind 判断监听地址是否对外暴露。
// 解析失败一律按「危险」处理，避免畸形地址绕过校验。
func isPublicBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// 非 IP 的主机名一律视为对外暴露
		return true
	}
	return !ip.IsLoopback()
}

// validateCIDRList 逐项校验来源白名单：每一项都必须是合法的 IP 或 CIDR，
// 且不能等价于「信任所有来源」。
//
// 空列表是合法的（表示未启用白名单），但列表**里**的空项不是：
// 它多半来自 "10.0.0.0/8, ,1.2.3.4" 这种手写串，而它同时会让管理员以为
// 该项已经生效。
func validateCIDRList(name string, list []string) error {
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			return fmt.Errorf("%s 中存在空项：白名单里的每一项都必须是 IP 或 CIDR", name)
		}
		if isTrustAll(v) {
			return fmt.Errorf("%s 不允许配置 %q：那等于不限制来源", name, v)
		}
		if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil {
			return fmt.Errorf("%s 中的 %q 不是合法的 IP 或 CIDR", name, v)
		}
	}
	return nil
}

// isTrustAll 判断网段是否等价于「信任所有来源」。
func isTrustAll(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	switch cidr {
	case "0.0.0.0/0", "::/0", "0.0.0.0", "::", "*", "any":
		return true
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := n.Mask.Size()
	return ones == 0 && bits > 0
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
