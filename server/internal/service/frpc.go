package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

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

	// 换凭据与让旧会话失效必须在**同一个事务**里。
	//
	// 分两步写会留下一个谁都说不清的中间态：凭据已经换掉、会话还没失效，
	// 而接口此时报错返回。用户以为没成功，实际旧凭据已经作废（客户端连不上），
	// 同时内存里的旧会话还在——插件热路径照样放行。两边都不对。
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.User{}).Where("id = ?", u.ID).
			Update("client_secret", secret).Error; err != nil {
			return err
		}
		return revokeClientSessionsTx(tx, u.ID)
	})
	if err != nil {
		return "", err
	}
	u.ClientSecret = secret

	// 内存会话在事务提交之后再清。它不参与事务，但顺序不能反：
	// 先清内存、事务又失败的话，用户手里那份凭据仍然有效，
	// 而他的会话已经没了——客户端会被迫重连一次。
	s.Runtime.DropUserSessions(u.ID)
	return secret, nil
}

// RevokeClientSessions 让某用户已建立的客户端会话立即失效。
//
// 两处都要清，缺一不可：
//
//   - 数据库会话表：插件在内存未命中时回落查它（run_id + online=true）；
//   - 内存会话：插件热路径（onNewUserConn，每次新建用户连接都经过）
//     只查内存，命中后只校验配额就放行——凭据轮换后它照样放行。
//
// 说明清楚边界：已经建立的数据连接断不掉（那是 frps 与 frpc 之间的事，
// 插件无权插手），但此后**新建**的连接会走凭据复核并被拒绝。
func (s *Services) RevokeClientSessions(userID uint) error {
	if err := revokeClientSessionsTx(s.DB, userID); err != nil {
		return err
	}
	s.Runtime.DropUserSessions(userID)
	return nil
}

// revokeClientSessionsTx 是「让数据库里的会话失效」这一步，
// 可被包进调用方自己的事务。
func revokeClientSessionsTx(tx *gorm.DB, userID uint) error {
	return tx.Model(&model.ClientSession{}).
		Where("user_id = ?", userID).
		Update("online", false).Error
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
		FrpsToken: s.Cfg.FrpsToken,
		// 用 TunnelDomain()（数据库设置优先）：管理端改完域名后 frps 与
		// Caddy 已按新域名重建，而面板容器不会重启——这里返回旧域名的话，
		// 客户端就会把子域名的访问地址拼成已经不存在的那个域名。
		TunnelDomain:  s.TunnelDomain(),
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

	// 必须写 console（stdout）：客户端靠解析 frpc 的输出判断「这条隧道到底
	// 起来没有」——`start proxy success` 会触发界面上的「隧道启动成功 + 可用
	// 地址」，错误行则用于显示「为什么一直连不上」。
	//
	// 这里曾经写的是 ./frpc.log：日志全落到文件里，客户端读到的 stdout 始终
	// 是空的，于是那两条提示**永远不会出现**——用户只看到「已启动 frpc（PID …）」
	// 之后就再无下文，分不清是在连、还是已经连上了。
	//
	// maxDays 只对文件输出有意义，改成 console 后一并去掉。
	b.WriteString("log.to = \"console\"\n")
	b.WriteString("log.level = \"info\"\n")

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
