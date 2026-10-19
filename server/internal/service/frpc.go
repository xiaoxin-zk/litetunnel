package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const MetaTokenKey = "token"

const FrpUserPrefix = "lt_u"

func FrpUserOf(userID uint) string {
	return FrpUserPrefix + strconv.FormatUint(uint64(userID), 10)
}

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

func (s *Services) EnsureClientSecret(u *model.User) (string, error) {
	if u.ClientSecret != "" {
		return u.ClientSecret, nil
	}
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}

	res := s.DB.Model(&model.User{}).
		Where("id = ? AND (client_secret IS NULL OR client_secret = '')", u.ID).
		Update("client_secret", secret)
	if res.Error != nil {
		return "", res.Error
	}
	if res.RowsAffected > 0 {
		u.ClientSecret = secret
		return secret, nil
	}

	var fresh model.User
	if err := s.DB.Select("id", "client_secret").First(&fresh, u.ID).Error; err != nil {
		return "", err
	}
	if fresh.ClientSecret == "" {
		return "", ErrNotFound
	}
	u.ClientSecret = fresh.ClientSecret
	return fresh.ClientSecret, nil
}

func (s *Services) ResetClientSecret(u *model.User) (string, error) {
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}

	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var cur model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").First(&cur, u.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		res := tx.Model(&model.User{}).Where("id = ?", u.ID).
			Update("client_secret", secret)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return revokeClientSessionsTx(tx, u.ID)
	})
	if err != nil {
		return "", err
	}
	u.ClientSecret = secret

	s.Runtime.DropUserSessions(u.ID)
	return secret, nil
}

func (s *Services) RevokeClientSessions(userID uint) error {
	if err := revokeClientSessionsTx(s.DB, userID); err != nil {
		return err
	}
	s.Runtime.DropUserSessions(userID)
	return nil
}

func revokeClientSessionsTx(tx *gorm.DB, userID uint) error {
	return tx.Model(&model.ClientSession{}).
		Where("user_id = ?", userID).
		Update("online", false).Error
}

func VerifyClientSecret(expected, got string) bool {
	if expected == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

type ClientInfo struct {
	ServerAddr    string `json:"server_addr"`
	ServerPort    int    `json:"server_port"`
	User          string `json:"user"`
	Token         string `json:"token"`
	FrpsToken     string `json:"frps_token"`
	TunnelDomain  string `json:"tunnel_domain"`
	ProxyNameFmt  string `json:"proxy_name_format"`
	BandwidthUnit string `json:"bandwidth_unit"`
	FrontendURL   string `json:"frontend_url"`
}

// FrontendURL 是用户在浏览器访问面板的完整地址（可带端口），
// 作为接入信息里的「服务器地址」展示。未配置时回落到面板对外地址，保证这一栏永远有值可复制。
// 留空时回落到面板对外地址，保证接入信息这一栏永远有值可复制。
func (s *Services) FrontendURL() string {
	if v := strings.TrimRight(strings.TrimSpace(s.Settings.Get(KeySiteFrontendURL)), "/"); v != "" {
		return v
	}
	return strings.TrimRight(s.UserPublicURL(), "/")
}

func (s *Services) GatewayEndpoint() (string, int) {
	host := strings.TrimSpace(s.Settings.Get(KeyGatewayHost))
	// 留空时回落到服务端配置：页面写着「可留空」，下发空地址会让客户端连不上。
	if host == "" && s.Cfg != nil {
		host = strings.TrimSpace(s.Cfg.GatewayHost)
	}
	port := s.Settings.Int(KeyGatewayPort)
	if port <= 0 || port > 65535 {
		port = s.Cfg.GatewayPort
	}
	if port <= 0 || port > 65535 {
		port = 7001
	}
	return host, port
}

func (s *Services) BuildClientInfo(u *model.User) (*ClientInfo, error) {
	secret, err := s.EnsureClientSecret(u)
	if err != nil {
		return nil, err
	}
	gatewayHost, gatewayPort := s.GatewayEndpoint()
	return &ClientInfo{
		ServerAddr:    gatewayHost,
		ServerPort:    gatewayPort,
		User:          FrpUserOf(u.ID),
		Token:         secret,
		FrpsToken:     s.Cfg.FrpsToken,
		TunnelDomain:  s.TunnelDomain(),
		ProxyNameFmt:  "{user}.{name}",
		BandwidthUnit: "MB/KB (字节/秒)",
		FrontendURL:   s.FrontendURL(),
	}, nil
}

func (s *Services) BuildFrpcConfig(u *model.User, tunnels []model.Tunnel) (string, error) {
	info, err := s.BuildClientInfo(u)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(s.FrpcConfigHeader(info))

	if len(tunnels) == 0 {
		b.WriteString("\n# 当前账号还没有可用隧道，请先在控制台创建。\n")
		return b.String(), nil
	}

	limit := s.EffectiveBandwidth(u)
	for _, t := range tunnels {
		b.WriteString(s.FrpcConfigProxy(u, t, limit))
	}
	return b.String(), nil
}

func (s *Services) FrpcConfigHeader(info *ClientInfo) string {
	var b strings.Builder
	b.WriteString("# ============================================================\n")
	b.WriteString("# LiteTunnel 客户端配置（由控制台自动生成）\n")
	b.WriteString("# 修改本文件不会绕过服务端限制，请通过控制台调整隧道。\n")
	b.WriteString("# ============================================================\n\n")
	fmt.Fprintf(&b, "serverAddr = %s\n", tomlString(info.ServerAddr))
	fmt.Fprintf(&b, "serverPort = %d\n\n", info.ServerPort)

	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %s\n\n", tomlString(info.FrpsToken))

	fmt.Fprintf(&b, "user = %s\n", tomlString(info.User))
	fmt.Fprintf(&b, "metadatas = { %s = %s }\n\n", MetaTokenKey, tomlString(info.Token))

	b.WriteString("# 强制 TLS，禁止明文回退\n")
	b.WriteString("transport.tls.enable = true\n")
	fmt.Fprintf(&b, "transport.tls.serverName = %s\n\n", tomlString(info.ServerAddr))

	b.WriteString("log.to = \"console\"\n")
	b.WriteString("log.level = \"info\"\n")
	return b.String()
}

func (s *Services) FrpcConfigProxy(u *model.User, t model.Tunnel, bandwidthLimit int64) string {
	if t.Status != model.TunnelStatusActive {
		return ""
	}

	var b strings.Builder
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
	if limit := FormatBandwidth(bandwidthLimit); limit != "" {
		fmt.Fprintf(&b, "transport.bandwidthLimit = %s\n", tomlString(limit))
		b.WriteString("transport.bandwidthLimitMode = \"server\"\n")
	}
	return b.String()
}

func FrpcConfigRev(configText string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(configText))
	return strconv.FormatUint(h.Sum64(), 16)
}

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
