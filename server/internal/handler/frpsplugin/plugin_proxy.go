package frpsplugin

// 代理准入：新建 / 关闭 / 心跳。
//
// 这些回调决定一条隧道能否上线、参数是否被篡改，以及限速与端口如何下发。

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

type closeProxyContent struct {
	User      userInfo `json:"user"`
	ProxyName string   `json:"proxy_name"`
}

type pingContent struct {
	User         userInfo `json:"user"`
	PrivilegeKey string   `json:"privilege_key"`
	Timestamp    int64    `json:"timestamp"`
}

// Handler 处理 frps 插件回调。

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
	// 配额与会话撤销的判定要与 NewUserConn 一致：那边优先用会话级快照，
	// 这边若只看本机全局缓存，多副本下会出现「配额已放宽仍拒注册」或
	// 「会话已撤销却注册成功、后续连接全被拒」这种自相矛盾的结果。
	if blocked, exceeded, ok := h.svc.SessionGuard(content.User.RunID); ok {
		if blocked {
			return deny("账号已被禁用")
		}
		if exceeded {
			return deny("流量额度已用尽，请兑换流量或联系管理员")
		}
	} else if h.svc.Runtime.IsQuotaExceeded(u.ID) {
		return deny("流量额度已用尽，请兑换流量或联系管理员")
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

func (h *Handler) onCloseProxy(req *request) response {
	var content closeProxyContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return allow()
	}
	if content.User.RunID != "" {
		h.svc.Runtime.TouchSession(content.User.RunID)
	}
	return allow()
}

func (h *Handler) onPing(req *request) response {
	var content pingContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return allow()
	}
	if content.User.RunID != "" {
		h.svc.Runtime.TouchSession(content.User.RunID)
		h.svc.TouchClientSession(content.User.RunID)
		// 顺带按需刷新会话的准入快照：多副本时账号可能在别的实例被禁用/超额，
		// 本地内存标记不会变。放在 Ping（周期性事件）而不是每次新建连接，
		// 既能让状态在一个 Ping 周期内收敛，又不会把查库压到连接热路径上。
		h.svc.RefreshSessionGuard(content.User.RunID)
	}
	return allow()
}
