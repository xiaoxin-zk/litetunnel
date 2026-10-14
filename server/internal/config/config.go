// Package config 负责集中加载运行期配置。
//
// 安全约定：本项目所有与部署环境相关的值（公网 IP、域名、密钥）一律通过
// 环境变量注入，源码与默认值中不得出现任何真实地址。
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const placeholderPrefix = "CHANGE_ME"

// Config 为控制面全部可配置项。
type Config struct {
	Env      string
	LogLevel string

	// 存储
	DBDriver string // sqlite | postgres
	DBDSN    string

	// 监听地址：用户侧对公网，管理侧仅本机
	UserAddr      string
	UserPublicURL string
	AdminAddr     string

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

	// ClientDistDir 存放对外分发的客户端安装包目录，由控制台列出供下载。
	ClientDistDir string

	// 两个控制台的前端构建产物目录。目录不存在时服务以纯 API 模式运行（开发用）。
	UserWebDir  string
	AdminWebDir string

	// TrustedProxies 是允许其转发头生效的反向代理地址。
	// 默认为回环地址（反代与本服务同机），避免客户端伪造 X-Forwarded-For 绕过限流。
	TrustedProxies []string

	TrafficPollInterval time.Duration

	UserJWTExpire  time.Duration
	AdminJWTExpire time.Duration
}

// Load 从环境变量装载配置并做必要校验。
func Load() (*Config, error) {
	c := &Config{
		Env:      env("LT_ENV", "development"),
		LogLevel: env("LT_LOG_LEVEL", "info"),

		DBDriver: env("LT_DB_DRIVER", "sqlite"),
		DBDSN:    env("LT_DB_DSN", "./data/litetunnel.db"),

		UserAddr:      env("LT_USER_ADDR", "0.0.0.0:8080"),
		UserPublicURL: strings.TrimRight(env("LT_USER_PUBLIC_URL", ""), "/"),
		AdminAddr:     env("LT_ADMIN_ADDR", "127.0.0.1:8443"),

		UserJWTSecret:  env("LT_USER_JWT_SECRET", ""),
		AdminJWTSecret: env("LT_ADMIN_JWT_SECRET", ""),
		APIKeyEncKey:   env("LT_APIKEY_ENC_KEY", ""),

		BootstrapAdminUser:     env("LT_BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapAdminPassword: env("LT_BOOTSTRAP_ADMIN_PASSWORD", ""),

		GatewayHost: env("LT_GATEWAY_HOST", ""),
		GatewayPort: envInt("LT_GATEWAY_PORT", 7000),

		FrpsToken:            env("LT_FRPS_TOKEN", ""),
		FrpsAPIAddr:          env("LT_FRPS_API_ADDR", "127.0.0.1:7500"),
		FrpsAPIUser:          env("LT_FRPS_API_USER", ""),
		FrpsAPIPassword:      env("LT_FRPS_API_PASSWORD", ""),
		FrpsPluginAllowCIDRs: splitCSV(env("LT_FRPS_PLUGIN_ALLOW_CIDR", "127.0.0.1/32,::1/128")),

		PortRangeStart:  envInt("LT_PORT_RANGE_START", 20000),
		PortRangeEnd:    envInt("LT_PORT_RANGE_END", 30000),
		MaxPortsPerUser: envInt("LT_MAX_PORTS_PER_USER", 10),

		TunnelDomain:  strings.ToLower(strings.TrimSpace(env("LT_TUNNEL_DOMAIN", ""))),
		ClientDistDir: env("LT_CLIENT_DIST_DIR", "./data/clients"),
		UserWebDir:     env("LT_USER_WEB_DIR", "./web/user/dist"),
		AdminWebDir:    env("LT_ADMIN_WEB_DIR", "./web/admin/dist"),
		TrustedProxies: splitCSV(env("LT_TRUSTED_PROXIES", "127.0.0.1,::1")),

		TrafficPollInterval: time.Duration(envInt("LT_TRAFFIC_POLL_INTERVAL", 30)) * time.Second,
		UserJWTExpire:       12 * time.Hour,
		AdminJWTExpire:      4 * time.Hour,
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// IsProd 返回是否生产环境。
func (c *Config) IsProd() bool { return c.Env == "production" }

func (c *Config) validate() error {
	if c.DBDriver != "sqlite" && c.DBDriver != "postgres" {
		return fmt.Errorf("LT_DB_DRIVER 仅支持 sqlite 或 postgres，当前为 %q", c.DBDriver)
	}
	if c.PortRangeStart <= 0 || c.PortRangeEnd <= c.PortRangeStart {
		return errors.New("LT_PORT_RANGE_START/END 配置非法")
	}
	if c.PortRangeStart < 1024 {
		return errors.New("端口池起始端口不得低于 1024（禁止占用特权端口）")
	}

	if !c.IsProd() {
		// 开发环境放宽，使用可复现的默认值，便于本地调试。
		if c.UserJWTSecret == "" {
			c.UserJWTSecret = "dev-user-secret-do-not-use-in-prod"
		}
		if c.AdminJWTSecret == "" {
			c.AdminJWTSecret = "dev-admin-secret-do-not-use-in-prod"
		}
		if c.APIKeyEncKey == "" {
			c.APIKeyEncKey = "dev-apikey-key-00000000000000000000"
		}
		if c.BootstrapAdminPassword == "" {
			c.BootstrapAdminPassword = "admin12345"
		}
		if c.GatewayHost == "" {
			c.GatewayHost = "127.0.0.1"
		}
		return nil
	}

	// 生产环境强制校验，避免带着占位符上线。
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
	if len(c.FrpsPluginAllowCIDRs) == 0 {
		missing = append(missing, "LT_FRPS_PLUGIN_ALLOW_CIDR")
	}

	if len(missing) > 0 {
		return fmt.Errorf("生产环境缺少或仍为占位符的配置项: %s", strings.Join(missing, ", "))
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
	if strings.HasPrefix(c.AdminAddr, "0.0.0.0") || strings.HasPrefix(c.AdminAddr, ":") {
		return errors.New("生产环境禁止将管理后台监听在 0.0.0.0，请使用 127.0.0.1:port 并通过本机反代访问")
	}
	return nil
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
