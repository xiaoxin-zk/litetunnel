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

func localPortRange() (lo, hi int, err error) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("无法解析 ip_local_port_range: %q", strings.TrimSpace(string(raw)))
	}
	nlo, err1 := strconv.Atoi(fields[0])
	nhi, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || nlo <= 0 || nhi <= nlo {
		return 0, 0, fmt.Errorf("ip_local_port_range 取值异常: %q", strings.TrimSpace(string(raw)))
	}
	return nlo, nhi, nil
}

var Version = "dev"

// DisplayVersion 返回去掉「v」前缀的纯版本号（如 1.2.3）。
// CI 把 tag 原文（v1.2.3）注入进来，而前端统一自己加 v 前缀展示；
// 后端 HTTP 出口若带 v，面板就会出现 vv1.2.3。所有对外出口都用这里。
func DisplayVersion() string {
	return strings.TrimPrefix(Version, "v")
}

type Config struct {
	Env      string
	LogLevel string

	DBDriver string
	DBDSN    string

	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string

	UserAddr      string
	UserPublicURL string

	AdminPath string

	AdminAllowCIDRs []string

	UserJWTSecret  string
	AdminJWTSecret string
	APIKeyEncKey   string

	BootstrapAdminUser     string
	BootstrapAdminPassword string

	GatewayHost string
	GatewayPort int

	FrpsToken       string
	FrpsAPIAddr     string
	FrpsAPIUser     string
	FrpsAPIPassword string

	FrpsPluginAllowCIDRs []string

	PortRangeStart  int
	PortRangeEnd    int
	MaxPortsPerUser int

	TunnelDomain string

	VhostHTTPSPort int

	HTTPSProxyMode string

	ClientDistDir string

	UserWebDir  string
	AdminWebDir string

	TrustedProxies []string

	SMTP SMTPConfig

	TrafficPollInterval time.Duration

	MonitorDiskPath string

	UserJWTExpire  time.Duration
	AdminJWTExpire time.Duration

	GeneratedSecrets       []string
	EphemeralAdminPassword bool
	Warnings               []string
}

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	TLS      string
	SiteName string
}

func (s SMTPConfig) Enabled() bool {
	return s.Host != "" && s.User != "" && s.Password != ""
}

var intEnvKeys = []string{
	"LT_REDIS_DB",
	"LT_GATEWAY_PORT",
	"LT_PORT_RANGE_START",
	"LT_PORT_RANGE_END",
	"LT_MAX_PORTS_PER_USER",
	"LT_VHOST_HTTPS_PORT",
	"LT_SMTP_PORT",
	"LT_TRAFFIC_POLL_INTERVAL",
}

func validateEnvInts() error {
	for _, key := range intEnvKeys {
		v, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, err := strconv.Atoi(v); err != nil {
			return fmt.Errorf("%s 必须是整数，当前为 %q: %w", key, v, err)
		}
	}
	return nil
}

var numericEnvKeys = []string{
	"LT_GATEWAY_PORT", "LT_KCP_PORT", "LT_VHOST_HTTP_PORT", "LT_VHOST_HTTPS_PORT",
	"LT_USER_PORT", "LT_FRPS_API_PORT",
	"LT_PORT_RANGE_START", "LT_PORT_RANGE_END", "LT_MAX_PORTS_PER_USER",
	"LT_REDIS_DB",
}

var portEnvKeys = map[string]bool{
	"LT_GATEWAY_PORT": true, "LT_KCP_PORT": true, "LT_VHOST_HTTP_PORT": true,
	"LT_VHOST_HTTPS_PORT": true, "LT_USER_PORT": true, "LT_FRPS_API_PORT": true,
	"LT_PORT_RANGE_START": true, "LT_PORT_RANGE_END": true,
}

func validateNumericEnvs() error {
	for _, key := range numericEnvKeys {
		raw, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%s=%q 不是合法的整数", key, raw)
		}
		if portEnvKeys[key] && (n < 1 || n > 65535) {
			return fmt.Errorf("%s=%d 不在 1-65535 范围内", key, n)
		}
		if key == "LT_REDIS_DB" && n < 0 {
			return fmt.Errorf("LT_REDIS_DB=%d 不能为负数", n)
		}
		if key == "LT_MAX_PORTS_PER_USER" && n < 1 {
			return fmt.Errorf("LT_MAX_PORTS_PER_USER=%d 必须大于 0", n)
		}
	}
	for _, key := range []string{"LT_USER_ADDR", "LT_FRPS_API_ADDR"} {
		raw, ok := os.LookupEnv(key)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if err := validateHostPort(key, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateHostPort(key, raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.Contains(raw, "://"):
		return fmt.Errorf("%s=%q 不能带 scheme：只填 host:port", key, raw)
	case strings.ContainsAny(raw, "?#"):
		return fmt.Errorf("%s=%q 不能带 query 或 fragment", key, raw)
	case strings.Contains(raw, "@"):
		return fmt.Errorf("%s=%q 不能带 userinfo", key, raw)
	case strings.ContainsAny(raw, " \t\r\n"):
		return fmt.Errorf("%s=%q 不能包含空白", key, raw)
	}
	_, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return fmt.Errorf("%s=%q 不是合法的 host:port：%w", key, raw, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s 的端口 %q 不在 1-65535 范围内", key, portStr)
	}
	return nil
}

func Load() (*Config, error) {
	if err := validateNumericEnvs(); err != nil {
		return nil, err
	}
	if err := validateEnvInts(); err != nil {
		return nil, err
	}
	c := &Config{
		Env:      env("LT_ENV", "development"),
		LogLevel: env("LT_LOG_LEVEL", "info"),

		DBDriver:      env("LT_DB_DRIVER", "sqlite"),
		DBDSN:         env("LT_DB_DSN", "./data/litetunnel.db"),
		RedisAddr:     env("LT_REDIS_ADDR", ""),
		RedisPassword: env("LT_REDIS_PASSWORD", ""),
		RedisDB:       envInt("LT_REDIS_DB", 0),
		RedisPrefix:   env("LT_REDIS_PREFIX", "litetunnel:"),

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
		MonitorDiskPath:     strings.TrimSpace(env("LT_MONITOR_DISK_PATH", "/")),
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

func (c *Config) IsProd() bool { return c.Env == "production" }

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
	// 刻意不再把空的 LT_GATEWAY_HOST 默认成 127.0.0.1：
	// 那个值会被下发给客户端，外部机器连自己的回环，隧道必然建不起来。
	// 生产环境由 validate() 拒绝空值/回环，非生产环境只给出警告。
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

// isUnroutableGatewayHost 判断地址能否作为「客户端要连的网关」：
// 空值、localhost、回环、未指定地址（0.0.0.0 / ::）都不行。
func isUnroutableGatewayHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" || strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
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
	for _, item := range []struct {
		name string
		val  int
	}{
		{"LT_GATEWAY_PORT", c.GatewayPort},
		{"LT_VHOST_HTTPS_PORT", c.VhostHTTPSPort},
		{"LT_PORT_RANGE_END", c.PortRangeEnd},
	} {
		if item.val < 1 || item.val > 65535 {
			return fmt.Errorf("%s=%d 不在 1-65535 范围内", item.name, item.val)
		}
	}
	if c.MaxPortsPerUser < 1 {
		return fmt.Errorf("LT_MAX_PORTS_PER_USER=%d 必须大于 0", c.MaxPortsPerUser)
	}
	if lo, hi, err := localPortRange(); err == nil && c.PortRangeEnd >= lo && c.PortRangeStart <= hi {
		return fmt.Errorf("端口池 %d-%d 与内核临时端口段 %d-%d 重叠：监听端口撞上出站连接的源端口会导致偶发绑定失败"+
			"（请把 LT_PORT_RANGE_END 压到 %d 以下）",
			c.PortRangeStart, c.PortRangeEnd, lo, hi, lo-1)
	}

	for _, p := range c.TrustedProxies {
		if isTrustAll(p) {
			return fmt.Errorf("LT_TRUSTED_PROXIES 不允许配置 %q：那会让任意客户端伪造来源 IP", p)
		}
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			return fmt.Errorf("LT_TRUSTED_PROXIES 中的 %q 不是合法的 IP 或 CIDR", p)
		}
	}
	if err := validateCIDRList("LT_ADMIN_ALLOW_CIDR", c.AdminAllowCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("LT_FRPS_PLUGIN_ALLOW_CIDR", c.FrpsPluginAllowCIDRs); err != nil {
		return err
	}

	if !c.IsProd() {
		if isPublicBind(c.UserAddr) {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("当前为非生产环境且监听在 %s，任何人都可能访问；请勿用于公网", c.UserAddr))
		}
		if c.UserPublicURL == "" {
			c.Warnings = append(c.Warnings,
				"未配置 LT_USER_PUBLIC_URL，找回密码的邮件不会发出（重置链接无法生成）；本地调试请设为 http://localhost:<端口>")
		}
		if isUnroutableGatewayHost(c.GatewayHost) {
			c.Warnings = append(c.Warnings,
				"LT_GATEWAY_HOST 为空或为回环/0.0.0.0：客户端会拿到这个地址，外部机器将连不上；公网部署前请改成可访问的域名或 IP")
		}
		return nil
	}

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
	require("LT_USER_PUBLIC_URL", c.UserPublicURL)

	if len(missing) > 0 {
		return fmt.Errorf("生产环境缺少或仍为占位符的配置项: %s", strings.Join(missing, ", "))
	}
	if isUnroutableGatewayHost(c.GatewayHost) {
		return errors.New("LT_GATEWAY_HOST 必须是客户端可访问的公网域名或 IP，不能是回环地址、0.0.0.0 或空值")
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
	if len(c.AdminAllowCIDRs) == 0 {
		c.Warnings = append(c.Warnings,
			"管理后台当前对公网开放（未配置 LT_ADMIN_ALLOW_CIDR）。"+
				"请务必启用管理员双因素认证，否则仅有密码一道防线")
	}
	return nil
}

var reservedPathPrefixes = []string{"/api", "/healthz", "/assets", "/favicon"}

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
		return true
	}
	return !ip.IsLoopback()
}

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
