package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
//
// 写入必须是**条件**的（仅当字段仍为空）：
//
// 两个「首次接入」请求并发时，无条件写会让后到的覆盖先到的。先到那个请求
// 已经把密钥写进了响应，客户端拿它去连，结果库里是被另一个覆盖后的值——
// 表现为「第一次登录失败，重试一次就好」，而且日志里没有任何异常。
//
// 条件更新没命中说明别人已经写好了：以库里的值为准返回，本轮生成的随机值丢弃。
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

	// 被并发方抢先写入：读回最终值。
	var fresh model.User
	if err := s.DB.Select("id", "client_secret").First(&fresh, u.ID).Error; err != nil {
		return "", err
	}
	if fresh.ClientSecret == "" {
		// 条件更新没命中、读回来却还是空：只可能是用户不存在或并发删除。
		return "", ErrNotFound
	}
	u.ClientSecret = fresh.ClientSecret
	return fresh.ClientSecret, nil
}

// ResetClientSecret 重置客户端接入凭据，旧客户端会立即失效。
func (s *Services) ResetClientSecret(u *model.User) (string, error) {
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}

	// 换凭据与让旧会话失效必须在**同一个事务**里，并在用户行锁内串行。
	//
	// 分两步写会留下一个谁都说不清的中间态：凭据已经换掉、会话还没失效，
	// 而接口此时报错返回。用户以为没成功，实际旧凭据已经作废（客户端连不上），
	// 同时内存里的旧会话还在——插件热路径照样放行。两边都不对。
	//
	// 行锁还防并发重置：两个请求都「成功」但库里只剩最后写入的那份明文，
	// 先返回的客户端拿到的已经作废。行锁让它们排队，并校验 RowsAffected，
	// 用户不存在时不再静默成功。
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

// CloseUserProxies 关闭某用户在 frps 侧的所有已建立代理，实现「立即断流」。
//
// 禁用/封禁账号时调用：只更新阻断标记与清会话，拦得住**新**连接，却拦不住
// 已经建立的代理流——frps 与 frpc 之间的数据连接会一直转发。逐个关闭该用户
// 名下的代理，frps 会下线它们、断开已建立的数据连接。
//
// gen 是「这次禁用」对应的状态代次（见 bumpUserStatusGen）。断流要访问 frps
// 管理接口，最长可拖十几秒，而这段时间里用户可以已经被重新启用：客户端会
// 重连、建立新代理，甚至新代理就出现在下面这份列表里。此时继续关就不是
// 「断掉禁用前的流量」，而是把刚放行的人又踢下线。
//
// 复查与关闭都放在**该用户的锁**内，且粒度是一条代理：状态变更路径
// （启用/禁用/改配额）同样持这把锁，因此「确认代次未变」与「发出关闭请求」
// 之间不可能插进一次重新启用。只复查不放锁的话，两者之间仍有窗口——
// 检查通过、请求发出前用户被启用，那条新代理照样会被关掉。
//
// 锁的粒度是单条而不是整段：整段持锁会在 frps 变慢时把启用操作挡十几秒，
// 而用户点「启用」时最不该看到的就是长时间无响应。
//
// notAfter 是「本次禁用生效的时刻」。跨实例时锁与代次都挡不住最后一次竞态：
// 另一台实例上的启用可以正好插在查库之后、关闭请求到达 frps 之前。所以再
// 加一道基于 frps 自身数据的判据——代理的 lastStartAt：
//
//   - 新代理一定晚于 notAfter 启动（客户端重连会重新注册，frps 会刷新该时间），
//     这类直接跳过；
//   - 只有「禁用前就在跑、期间没有重新注册」的代理才关。
//
// 这是现有接口条件下能做到的最强保证。彻底原子需要 frps 关闭接口支持
// 「按版本条件关闭」，那是协议改动，不在本服务控制范围内。
//
// 关闭失败不中断：能关一个是一个，失败的由「客户端重连被拒」兜底。
func (s *Services) CloseUserProxies(ctx context.Context, userID uint, gen uint64, notAfter time.Time) {
	// gen 来自 users.state_version（见 AdminSetUserStatus），是跨实例的版本。
	// 内存里可能还没有这个用户（刚启动，或状态变更发生在别的实例上），
	// 所以「0」只能当作「没有信息」，不能当成「版本不符」。
	if cached := s.userStatusGen(userID); cached != 0 && cached != gen {
		log.Printf("[user] 用户 %d 的状态在断流开始前已变更，跳过本次断流", userID)
		return
	}
	prefix := FrpUserOf(userID) + "."
	proxies, err := s.Frps.ListProxies(ctx)
	if err != nil {
		log.Printf("[user] 拉取代理列表失败，本次无法主动断流（新连接仍会被拒）: %v", err)
		return
	}
	for _, p := range proxies {
		if !strings.HasPrefix(p.Name, prefix) {
			continue
		}
		// 代理在禁用生效之后才启动 = 重新启用后的新连接（或被客户端重连
		// 重新注册过），关掉它就等于把刚放行的人又踢下线。
		// lastStartAt 缺失（老版本 frps）时不作判断，退回只靠代次与锁。
		if p.Status.LastStartAt > 0 && !notAfter.IsZero() {
			if startedAt := time.Unix(p.Status.LastStartAt, 0); startedAt.After(notAfter) {
				log.Printf("[user] 用户 %d 的代理 %q 在禁用之后才启动（%s），跳过关闭",
					userID, p.Name, startedAt.Format(time.RFC3339))
				continue
			}
		}
		// 复查代次与关闭动作在同一把用户锁内完成：列表是几秒前拉的，
		// 期间状态可能已经翻转，而这个窗口必须以锁关闭，不能只靠一次读。
		lock := s.userLock(userID)
		lock.Lock()
		if cached := s.userStatusGen(userID); cached != 0 && cached != gen {
			lock.Unlock()
			log.Printf("[user] 用户 %d 的状态在断流过程中已变更，停止关闭剩余代理（避免误伤重新启用后的新代理）", userID)
			return
		}
		// 进程内代次只覆盖「本实例」。启用请求完全可能落在另一台实例上，
		// 而那台实例写下的状态版本，这里只能查库才看得到。
		// 查不到账号（已删除）或数据库暂时不可用时不据此中止：禁用本身
		// 已经生效，新连接会被拒，漏关的代理影响远小于误判。
		if dbGen, err := s.userStateVersionFromDB(userID); err == nil && dbGen != gen {
			lock.Unlock()
			log.Printf("[user] 用户 %d 的状态在其他实例上已变更（版本 %d ≠ %d），停止关闭剩余代理",
				userID, dbGen, gen)
			return
		}
		err := s.Frps.CloseProxy(ctx, p.Name)
		lock.Unlock()
		if err != nil {
			log.Printf("[user] 关闭用户 %d 的代理 %q 失败: %v", userID, p.Name, err)
			continue
		}
		log.Printf("[user] 已关闭用户 %d 的代理 %q", userID, p.Name)
	}
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
	ServerAddr    string `json:"server_addr"`
	ServerPort    int    `json:"server_port"`
	User          string `json:"user"`
	Token         string `json:"token"`
	FrpsToken     string `json:"frps_token"`
	TunnelDomain  string `json:"tunnel_domain"`
	ProxyNameFmt  string `json:"proxy_name_format"`
	BandwidthUnit string `json:"bandwidth_unit"`
}

// BuildClientInfo 组装客户端接入信息。
func (s *Services) BuildClientInfo(u *model.User) (*ClientInfo, error) {
	secret, err := s.EnsureClientSecret(u)
	if err != nil {
		return nil, err
	}
	return &ClientInfo{
		ServerAddr: s.Cfg.GatewayHost,
		ServerPort: s.Cfg.GatewayPort,
		User:       FrpUserOf(u.ID),
		Token:      secret,
		FrpsToken:  s.Cfg.FrpsToken,
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
	b.WriteString(s.FrpcConfigHeader(info))

	if len(tunnels) == 0 {
		b.WriteString("\n# 当前账号还没有可用隧道，请先在控制台创建。\n")
		return b.String(), nil
	}

	// 限速只算一次：它是分组当前值，同一轮里不会变，逐隧道重算纯属浪费。
	limit := s.EffectiveBandwidth(u)
	for _, t := range tunnels {
		b.WriteString(s.FrpcConfigProxy(u, t, limit))
	}
	return b.String(), nil
}

// FrpcConfigHeader 渲染配置的公共头部（服务端地址、鉴权、日志设置）。
//
// 拆出来是为了让「单条隧道的配置摘要」与「完整配置」用**同一份**渲染代码
// （见 FrpcConfigRev）：两处各写一遍，迟早会有一处忘了同步。
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
	return b.String()
}

// FrpcConfigProxy 渲染单条隧道的 [[proxies]] 段；未启用时返回空串。
//
// bandwidthLimit 由调用方用 EffectiveBandwidth 算好传进来，不能在这里自己算：
// 分组过期或未绑定的账号会走 EffectiveGroup → defaultGroup() 的回落路径，
// 那是**一次数据库查询**。而 /client/info 要为每条隧道算配置摘要、客户端每
// 20 秒同步一次，逐条重算就是典型的 N+1——隧道越多、越持续。
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
	// 限速取分组当前值，与强制下发（onNewProxy）和界面展示同一来源。
	//
	// 虽然服务端会在 NewProxy 时覆盖这个声明、改错了也不影响实际生效，
	// 但生成的文件要给用户看——里面写着一个旧值会让人以为限制就是那样。
	// 值由调用方传入（见函数注释）：这里再算一次就是每条隧道一次查询。
	if limit := FormatBandwidth(bandwidthLimit); limit != "" {
		fmt.Fprintf(&b, "transport.bandwidthLimit = %s\n", tomlString(limit))
		// 由服务端强制限速，客户端侧无法通过改配置绕过。
		b.WriteString("transport.bandwidthLimitMode = \"server\"\n")
	}
	return b.String()
}

// FrpcConfigRev 返回配置文本的短摘要，供客户端跳过没变化的配置请求。
//
// 摘要取的是**渲染结果**本身，而不是「隧道行的 updated_at + 设置版本」这类
// 推断：任何影响输出字节的输入（隧道字段、分组限速、站点设置、客户端密钥、
// 服务端地址）变化都会让摘要变化，不存在「漏了某个字段，客户端一直用旧配置」
// 的风险。客户端拿到的 config_rev 与它本地缓存的文本一一对应。
func FrpcConfigRev(configText string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(configText))
	return strconv.FormatUint(h.Sum64(), 16)
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
