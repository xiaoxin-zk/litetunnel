package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// MetaTokenKey 是客户端在 frpc 配置 metadatas 中携带接入凭据的键名。
const MetaTokenKey = "token"

// FrpUserPrefix 是 frp 配置里 user 字段的前缀，后接**不可变的用户 ID**。
//
// 为什么用 ID 而不是用户名：frp 会把 user 作为代理名前缀，插件回调也靠它
// 反解调用方身份。若用用户名，用户一旦改名，所有已下发的客户端配置立即失效，
// 且需要重建全部会话。改用 ID 后用户名可自由变更。
const FrpUserPrefix = "lt_u"

// FrpUserOf 生成 frp 的 user 字段，形如 lt_u12。
func FrpUserOf(userID uint) string {
	return FrpUserPrefix + strconv.FormatUint(uint64(userID), 10)
}

// UserIDFromFrpUser 从 frp 的 user 字段还原用户 ID。
func UserIDFromFrpUser(frpUser string) (uint, bool) {
	rest, ok := strings.CutPrefix(frpUser, FrpUserPrefix)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(rest, 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

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
		User:          FrpUserOf(u.ID),
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
		// 限速取分组当前值，与强制下发（onNewProxy）和界面展示同一来源。
		//
		// 虽然服务端会在 NewProxy 时覆盖这个声明、改错了也不影响实际生效，
		// 但生成的文件要给用户看——里面写着一个旧值会让人以为限制就是那样。
		// EffectiveGroup 用的是已预加载的 u.Group，这里不产生额外查询。
		if limit := FormatBandwidth(s.EffectiveBandwidth(u)); limit != "" {
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
