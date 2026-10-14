package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// MetaTokenKey 是客户端在 frpc 配置 metadatas 中携带接入凭据的键名。
const MetaTokenKey = "token"

// ProxyNamePrefix 由 frp 自动把 user 作为 proxy 名前缀，
// 本平台统一以 lt_ 开头标识来源，便于在 frps 侧识别与过滤。
const ProxyNamePrefix = "lt_"

// EnsureClientSecret 确保用户拥有客户端接入凭据。
func (s *Services) EnsureClientSecret(u *model.User) (string, error) {
	if u.ClientSecret != "" {
		return u.ClientSecret, nil
	}
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("client_secret", secret).Error; err != nil {
		return "", err
	}
	u.ClientSecret = secret
	return secret, nil
}

// ResetClientSecret 重置客户端接入凭据，旧客户端会立即失效。
func (s *Services) ResetClientSecret(u *model.User) (string, error) {
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("client_secret", secret).Error; err != nil {
		return "", err
	}
	u.ClientSecret = secret
	return secret, nil
}

// VerifyClientSecret 常量时间比较，抵御时序侧信道。
func VerifyClientSecret(expected, got string) bool {
	if expected == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// ClientInfo 下发给客户端/控制台的接入信息。
type ClientInfo struct {
	ServerAddr     string `json:"server_addr"`
	ServerPort     int    `json:"server_port"`
	User           string `json:"user"`
	Token          string `json:"token"`
	FrpsToken      string `json:"frps_token"`
	TunnelDomain   string `json:"tunnel_domain"`
	ProxyNameFmt   string `json:"proxy_name_format"`
	BandwidthUnit  string `json:"bandwidth_unit"`
}

// BuildClientInfo 组装客户端接入信息。
func (s *Services) BuildClientInfo(u *model.User) (*ClientInfo, error) {
	secret, err := s.EnsureClientSecret(u)
	if err != nil {
		return nil, err
	}
	return &ClientInfo{
		ServerAddr:    s.Cfg.GatewayHost,
		ServerPort:    s.Cfg.GatewayPort,
		User:          ProxyNamePrefix + u.Username,
		Token:         secret,
		FrpsToken:     s.Cfg.FrpsToken,
		TunnelDomain:  s.Cfg.TunnelDomain,
		ProxyNameFmt:  "{user}.{name}",
		BandwidthUnit: "MB/KB (字节/秒)",
	}, nil
}

// BuildFrpcConfig 生成该用户完整的 frpc.toml。
//
// 生成结果完全由服务端决定：本地地址、远程端口、限速、加密开关均来自数据库，
// 客户端无法通过修改配置文件突破分组权限（服务端插件会再次校验）。
func (s *Services) BuildFrpcConfig(u *model.User, tunnels []model.Tunnel) (string, error) {
	info, err := s.BuildClientInfo(u)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# ============================================================\n")
	b.WriteString("# LiteTunnel 客户端配置（由控制台自动生成）\n")
	b.WriteString("# 修改本文件不会绕过服务端限制，请通过控制台调整隧道。\n")
	b.WriteString("# ============================================================\n\n")
	fmt.Fprintf(&b, "serverAddr = %s\n", tomlString(info.ServerAddr))
	fmt.Fprintf(&b, "serverPort = %d\n\n", info.ServerPort)

	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %s\n\n", tomlString(info.FrpsToken))

	// user 会被 frp 用作 proxy 名前缀，服务端插件据此定位账号。
	fmt.Fprintf(&b, "user = %s\n", tomlString(info.User))
	fmt.Fprintf(&b, "metadatas = { %s = %s }\n\n", MetaTokenKey, tomlString(info.Token))

	b.WriteString("# 强制 TLS，禁止明文回退\n")
	b.WriteString("transport.tls.enable = true\n")
	fmt.Fprintf(&b, "transport.tls.serverName = %s\n\n", tomlString(info.ServerAddr))

	b.WriteString("log.to = \"./frpc.log\"\n")
	b.WriteString("log.level = \"info\"\n")
	b.WriteString("log.maxDays = 7\n")

	if len(tunnels) == 0 {
		b.WriteString("\n# 当前账号还没有可用隧道，请先在控制台创建。\n")
		return b.String(), nil
	}

	for _, t := range tunnels {
		if t.Status != model.TunnelStatusActive {
			continue
		}
		b.WriteString("\n[[proxies]]\n")
		fmt.Fprintf(&b, "name = %s\n", tomlString(t.Name))
		fmt.Fprintf(&b, "type = %s\n", tomlString(t.Type))
		fmt.Fprintf(&b, "localIP = %s\n", tomlString(t.LocalIP))
		fmt.Fprintf(&b, "localPort = %d\n", t.LocalPort)

		switch t.Type {
		case model.ProxyTypeTCP, model.ProxyTypeUDP:
			fmt.Fprintf(&b, "remotePort = %d\n", t.RemotePort)
		case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
			if t.Domain != "" {
				fmt.Fprintf(&b, "customDomains = [%s]\n", tomlString(t.Domain))
			} else if t.Subdomain != "" {
				fmt.Fprintf(&b, "subdomain = %s\n", tomlString(t.Subdomain))
			}
		}

		if t.UseEncryption {
			b.WriteString("transport.useEncryption = true\n")
		}
		if t.UseCompression {
			b.WriteString("transport.useCompression = true\n")
		}
		if limit := FormatBandwidth(t.BandwidthLimit); limit != "" {
			fmt.Fprintf(&b, "transport.bandwidthLimit = %s\n", tomlString(limit))
			// 由服务端强制限速，客户端侧无法通过改配置绕过。
			b.WriteString("transport.bandwidthLimitMode = \"server\"\n")
		}
	}
	return b.String(), nil
}

// tomlString 输出安全的 TOML 基本字符串。
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
