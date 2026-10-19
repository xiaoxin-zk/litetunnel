package frpsplugin

// 代理准入：新建代理。
//
// 这个回调决定一条隧道能否上线、参数是否被篡改，以及限速如何下发。
// 它与 plugin_conn.go 共用同一套「账号现在能不能用」的判断，但触发频率
// 低得多（每条隧道一次，而不是每个连接一次），所以在这里可以承担更
// 保守的判定：宁可拒绝一次注册让用户重连，也不放行一个已禁用的账号。

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type newProxyContent struct {
	User               userInfo          `json:"user"`
	ProxyName          string            `json:"proxy_name"`
	ProxyType          string            `json:"proxy_type"`
	UseEncryption      bool              `json:"use_encryption"`
	UseCompression     bool              `json:"use_compression"`
	BandwidthLimit     string            `json:"bandwidth_limit"`
	BandwidthLimitMode string            `json:"bandwidth_limit_mode"`
	Group              string            `json:"group"`
	GroupKey           string            `json:"group_key"`
	Metas              map[string]string `json:"metas"`
	Annotations        map[string]string `json:"annotations"`
	RemotePort         int               `json:"remote_port"`
	CustomDomains      []string          `json:"custom_domains"`
	SubDomain          string            `json:"subdomain"`
	Locations          []string          `json:"locations"`
	HTTPUser           string            `json:"http_user"`
	HTTPPwd            string            `json:"http_pwd"`
	HostHeaderRewrite  string            `json:"host_header_rewrite"`
	Headers            map[string]string `json:"headers"`
	ResponseHeaders    map[string]string `json:"response_headers"`
	RouteByHTTPUser    string            `json:"route_by_http_user"`
	Sk                 string            `json:"sk"`
	AllowUsers         []string          `json:"allow_users"`
	Multiplexer        string            `json:"multiplexer"`
}

func (h *Handler) onNewProxy(req *request) response {
	var content newProxyContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("代理参数解析失败")
	}
	if r, notReady := h.denyUntilGuardReady(); notReady {
		return r
	}

	// 传 metas：首次登录时会话尚未登记，需要靠它复核凭据。
	u, ok := h.resolveUser(content.User.User, content.User.RunID, content.User.Metas)
	if !ok {
		return deny("客户端未完成认证，请重启客户端后重试")
	}
	if u.Status != model.UserStatusActive {
		return deny("账号已被禁用")
	}
	// 配额与禁用的判定要与 NewUserConn 一致：那边优先用会话级快照，
	// 这边若只看本机全局缓存，多副本下会出现「配额已放宽仍拒注册」或
	// 「会话已撤销却注册成功、后续连接全被拒」这种自相矛盾的结果。
	//
	// 快照未建立时（新会话还没来得及 Ping 一次、或控制面刚重启）必须
	// 回落到本机标记，且**两个标记都要看**：这里曾经只查超额，于是刚被
	// 禁用、会话缓存又恰好没命中的账号仍能注册代理成功——注册那一刻
	// frps 就把端口/域名绑上了，用户看到的是「隧道显示在线但连不上」，
	// 直到下一次新建连接才被拒。禁用生效的时点被推迟到一个不可预测的
	// 未来事件（下一次连接），这正是「禁用」语义最不该有的样子。
	if blocked, exceeded, ok := h.svc.SessionGuard(content.User.RunID); ok {
		if blocked {
			return deny("账号已被禁用")
		}
		if exceeded {
			return deny("流量额度已用尽，请兑换流量或联系管理员")
		}
	} else {
		// 没有会话级快照：只能读本机内存标记。这是一份**可能过期的快照**，
		// 所以要求整个读取过程处于一个稳定的准入版本窗口内（见 localAdmission）。
		blocked, exceeded, ok := h.localAdmission(u.ID)
		if !ok {
			// 读不出可信判定就拒绝注册（fail-closed）。
			//
			// 为什么不能「读不干净就按没禁用放行」：放行的后果是把一个可能
			// 已被禁用的账号的端口重新绑到公网，且没有任何后续事件会纠正
			// 它——代理一旦注册成功，后续连接准入走的是另一条路径，注册
			// 本身不会因为账号被禁用而自动撤销。而拒绝的代价只是一次重连：
			// 客户端会重试，下一轮就能读到稳定状态。两个方向的代价不对称，
			// 只能选拒绝。
			log.Printf("[plugin] 用户 %d 的准入状态在读取期间持续变化，无法确认是否已禁用，已拒绝注册", u.ID)
			return deny("账号状态正在变更，请稍后重试")
		}
		if blocked {
			return deny("账号已被禁用")
		}
		if exceeded {
			return deny("流量额度已用尽，请兑换流量或联系管理员")
		}
	}

	// frp 会把代理名规范成 "<user>.<proxy_name>"——也就是 frpc.toml 里的
	// user 加上隧道名（见 service.ClientInfo.ProxyNameFmt），而数据库里存的
	// 是不带前缀的隧道名。必须先把前缀拆掉再查库。
	//
	// 这里曾经直接拿 content.ProxyName 查库：真实客户端发来的 "lt_u1.mc"
	// 永远查不到数据库里的 "mc"，客户端就一直卡在「连接中」，而报错说的是
	// 「隧道不存在或不属于当前账号」——把排查方向指向了账号、权限、
	// 甚至是防火墙，与真正的原因（少了一步拆前缀）毫无关系。
	frpUser, tunnelName, ok := service.ParseProxyName(content.ProxyName)
	if !ok {
		log.Printf("[plugin] 代理名缺少用户前缀（proxy_name=%q, user=%q），已拒绝",
			content.ProxyName, content.User.User)
		return deny("代理名格式非法，请重新下载客户端配置")
	}
	// 前缀必须与本次回调认定的账号一致。
	//
	// u 是用凭据解析出来的，而前缀是客户端自己填在代理名里的。两者不一致
	// 说明它在伪造别人的身份标识。查库本身已按 u.ID 限定、跨不了账号，
	// 但这里显式挡住：前缀是身份标识，任何地方都不该允许它与账号脱钩。
	if frpUser != service.FrpUserOf(u.ID) {
		log.Printf("[plugin] 代理名前缀与账号不匹配（proxy_name=%q, user=%q, 期望前缀=%q），已拒绝",
			content.ProxyName, content.User.User, service.FrpUserOf(u.ID))
		return deny("代理名与当前账号不匹配")
	}

	t, err := h.svc.FindTunnelByName(u.ID, tunnelName)
	if err != nil {
		return deny("隧道不存在或不属于当前账号，请重新下载客户端配置")
	}
	if t.Status != model.TunnelStatusActive {
		return deny("隧道已被停用")
	}
	if !strings.EqualFold(t.Type, content.ProxyType) {
		return deny("隧道协议与控制台下发的配置不一致")
	}

	switch t.Type {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		if content.RemotePort != t.RemotePort {
			return deny("远程端口与控制台下发的配置不一致")
		}
	case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
		if !domainMatched(t, &content) {
			return deny("访问域名与控制台下发的配置不一致")
		}
	}

	// 服务端强制限速：以**分组当前值**为准覆盖客户端声明，
	// 并把限速模式固定为 server，客户端改配置也无法绕过。
	//
	// 这里与展示层（userapi.tunnelVO）必须用同一个来源。
	// 读 t.BandwidthLimit 那份建隧道时的快照会造成更难查的不一致：
	// 界面上显示 4 Mbps，实际却按旧快照放行——用户看到的限制和
	// 真正生效的限制对不上，而他无从判断哪个是真的。
	changed := false
	want := service.FormatBandwidth(h.svc.EffectiveBandwidth(u))
	if want != "" {
		if content.BandwidthLimit != want {
			content.BandwidthLimit = want
			changed = true
		}
		if content.BandwidthLimitMode != "server" {
			content.BandwidthLimitMode = "server"
			changed = true
		}
	} else if content.BandwidthLimit != "" {
		// 分组未设限速时，清除客户端自行声明的限速值，避免其影响服务端配额统计。
		content.BandwidthLimit = ""
		content.BandwidthLimitMode = ""
		changed = true
	}

	if changed {
		return modify(content)
	}
	return allow()
}

// domainMatched 校验客户端声明的域名与数据库里的隧道配置**完全一致**。
//
// 为什么不能只要求「包含获准域名」：customDomains 由客户端提交，而 frpc 的
// 配置文件在用户手上。保留获准域名、再追加几个别的域名，就能通过「包含」
// 式的检查——frps 会把那些额外域名也路由到这条隧道，等于用别人（或平台
// 自己的）域名接管流量。所以要求集合一致：该用什么就用什么，多一个都不行。
func domainMatched(t *model.Tunnel, content *newProxyContent) bool {
	if t.Domain != "" {
		// 平台为自定义域名隧道下发的就是 customDomains = [<域名>]，恰好一项。
		return len(content.CustomDomains) == 1 &&
			strings.EqualFold(strings.TrimSpace(content.CustomDomains[0]), t.Domain) &&
			content.SubDomain == ""
	}
	if t.Subdomain != "" {
		// 二级域名隧道只应带 subdomain。两者同时出现时 frps 按 customDomains
		// 路由，那就绕开了「只能落在平台泛域名之下」这条限制（见 service
		// 里对自定义域名的校验）。
		return strings.EqualFold(strings.TrimSpace(content.SubDomain), t.Subdomain) &&
			len(content.CustomDomains) == 0
	}
	return false
}
