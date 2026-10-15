// Package frpsplugin 实现 frps 的服务端插件回调协议。
//
// 这是整个平台的信任边界：
//   - Login     校验每用户独立凭据，拒绝伪造身份的客户端
//   - NewProxy  校验隧道归属、协议、端口，并由服务端强制下发限速
//   - NewUserConn 在超额时实时拒绝新建用户连接，实现按配额断流
//
// 协议参考 frp v0.71 的 pkg/plugin/server：请求体为
// {"version":"0.1.0","op":"Login","content":{...}}，
// 响应体为 {"reject":bool,"reject_reason":string,"unchange":bool,"content":{...}}。
package frpsplugin

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// 回调操作名，与 frp 保持一致。
const (
	OpLogin       = "Login"
	OpNewProxy    = "NewProxy"
	OpCloseProxy  = "CloseProxy"
	OpPing        = "Ping"
	OpNewWorkConn = "NewWorkConn"
	OpNewUserConn = "NewUserConn"
)

type request struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type response struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason"`
	Unchange     bool   `json:"unchange"`
	Content      any    `json:"content,omitempty"`
}

// allow 放行且不修改内容。
//
// 必须显式设置 unchange=true：frp 侧在 unchange 为 false 时会用响应中的
// content 覆盖原始内容，若我们返回空 content 会把代理配置清零。
func allow() response { return response{Unchange: true} }

// deny 拒绝并给出原因，原因会回显到 frpc 日志，便于用户自查。
func deny(reason string) response {
	return response{Reject: true, RejectReason: reason, Unchange: true}
}

// modify 放行但替换内容。
func modify(content any) response {
	return response{Unchange: false, Content: content}
}

// ---- 回调内容结构 ----

type loginContent struct {
	Version       string            `json:"version"`
	Hostname      string            `json:"hostname"`
	Os            string            `json:"os"`
	Arch          string            `json:"arch"`
	User          string            `json:"user"`
	PrivilegeKey  string            `json:"privilege_key"`
	Timestamp     int64             `json:"timestamp"`
	RunID         string            `json:"run_id"`
	Metas         map[string]string `json:"metas"`
	ClientAddress string            `json:"client_address"`
}

type userInfo struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

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

type newUserConnContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	RemoteAddr string   `json:"remote_addr"`
}

// Handler 处理 frps 插件回调。
type Handler struct {
	svc        *service.Services
	allowCIDRs []*net.IPNet
}

// New 构造处理器。allowCIDRs 为允许调用本回调的来源网段。
func New(svc *service.Services, cidrs []string) *Handler {
	h := &Handler{svc: svc}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			h.allowCIDRs = append(h.allowCIDRs, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			h.allowCIDRs = append(h.allowCIDRs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return h
}

// Guard 校验来源 IP 是否在白名单内。
//
// frp 的 HTTP 插件协议不支持自定义鉴权头，因此以「仅回环/受信网段可达」作为
// 访问控制手段：该路由只注册在管理监听地址上，不会出现在公网端口。
func (h *Handler) Guard() gin.HandlerFunc {
	return func(c *gin.Context) {
		ipStr := c.ClientIP()
		ip := net.ParseIP(ipStr)
		if ip == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		for _, n := range h.allowCIDRs {
			if n.Contains(ip) {
				c.Next()
				return
			}
		}
		log.Printf("[plugin] 拒绝来自 %s 的插件回调请求", ipStr)
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// Handle 处理一次插件回调。
//
// 失败策略：**无法判断 op 时一律拒绝**（fail-closed）。
//
// 这是刻意的选择。Login 是整个平台的信任边界，如果请求体解析失败就放行，
// 那么任何能构造出解析失败的输入，都会让每用户凭据校验被静默跳过，
// 只剩全局 frps token 一道门（而那个 token 每个注册用户都能拿到）。
//
// 代价是 frp 协议若有变动会导致登录失败——但那属于**显式故障**，
// 比静默放行安全得多：前者立刻暴露，后者无声无息。
//
// 注意：只有「无法判断 op」时才需要这样保守。已识别的 op 由各自处理函数
// 决定失败策略（例如 Ping / CloseProxy 解析失败可以放行，它们不参与鉴权）。
func (h *Handler) Handle(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusOK, deny("插件请求读取失败"))
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("[plugin] 插件请求解析失败，已拒绝: %v", err)
		c.JSON(http.StatusOK, deny("插件请求格式非法"))
		return
	}

	var res response
	switch req.Op {
	case OpLogin:
		res = h.onLogin(&req)
	case OpNewProxy:
		res = h.onNewProxy(&req)
	case OpCloseProxy:
		res = h.onCloseProxy(&req)
	case OpPing:
		res = h.onPing(&req)
	case OpNewWorkConn:
		res = allow()
	case OpNewUserConn:
		res = h.onNewUserConn(&req)
	default:
		res = allow()
	}

	c.JSON(http.StatusOK, res)
}

// resolveUser 依据 frp 的 user / run_id / metas 定位平台账号。
//
// # 回落顺序
//
//  1. 内存会话缓存（onLogin 在凭据校验通过后写入）
//  2. 数据库会话表（同样只在凭据校验通过后写入，用于控制面重启后的过渡）
//  3. 用本次回调携带的 metas 复核每用户凭据
//
// # 为什么必须有第 3 条
//
// frp 在客户端**首次**登录时，插件拿到的 run_id 是空的——frps 要等插件
// 回调通过之后才生成它，并通过 LoginResp 回给客户端。而我们的 onLogin
// 需要 run_id 才能登记会话，于是：
//
//	Login(run_id="")  → 会话没写入（UpsertClientSession 直接 return）
//	NewProxy(run_id="X") → 查不到会话 → deny
//
// 现象是客户端永远停在「等待连接」，frps 反复记录
// 「客户端未完成认证，请重启客户端后重试」，而重启客户端毫无作用。
//
// # 第 3 条的安全性
//
// 它**不是**「信任 frpUser」。那等于绕过 Login 的凭据校验——知道全局
// token 的人就能冒充任意在线用户。这里校验的是**同一个每用户凭据**
// （frpc.toml 的 metadatas 里那一份），强度与 onLogin 完全一致。
//
// frp 官方文档明确：客户端登录时携带的全局 metadata 会在其他 RPC 请求里
// 附加到 user.metas 上，所以 NewProxy / NewWorkConn 阶段拿得到它。
//
// 复核通过后会顺手把会话补登记到真实 run_id 上，后续热路径
// （onNewUserConn，每次用户连接都经过）依然走内存查表，不产生额外开销。
func (h *Handler) resolveUser(frpUser, runID string, metas map[string]string) (*model.User, bool) {
	userID, ok := service.UserIDFromFrpUser(frpUser)
	if !ok {
		return nil, false
	}

	if runID != "" {
		// 1) 内存会话
		if s, ok := h.svc.Runtime.LookupSession(runID); ok {
			if s.UserID != userID {
				log.Printf("[plugin] run_id %s 声明的用户 ID %d 与会话不符（实际 %d），已拒绝",
					runID, userID, s.UserID)
				return nil, false
			}
			u, err := h.svc.LoadUser(s.UserID)
			if err != nil {
				return nil, false
			}
			return u, true
		}

		// 2) 数据库会话
		if sess, err := h.svc.FindTrustedClientSession(runID); err == nil {
			if sess.UserID != userID {
				log.Printf("[plugin] run_id %s 声明的用户 ID %d 与会话不符（实际 %d），已拒绝",
					runID, userID, sess.UserID)
				return nil, false
			}
			if u, err := h.svc.LoadUser(sess.UserID); err == nil {
				h.svc.Runtime.RecordLogin(runID, u.ID, u.Username)
				return u, true
			}
		}
	}

	// 3) 凭据复核（覆盖首次登录时 run_id 尚不存在的窗口）
	return h.authenticateByMeta(frpUser, runID, metas)
}

// authenticateByMeta 用回调携带的 metadata 复核每用户凭据。
//
// 复核通过后会把会话补登记到 run_id 上，使后续回调重新走上「查缓存」
// 这条快路径。run_id 为空时（理论上只在 Login 阶段，而 Login 不走这里）
// 跳过补登记，但不影响本次判定。
func (h *Handler) authenticateByMeta(frpUser, runID string, metas map[string]string) (*model.User, bool) {
	got := ""
	if metas != nil {
		got = metas[service.MetaTokenKey]
	}
	if got == "" {
		// 这条日志是排查「客户端停在等待连接」的第一线索：
		// 它说明本次回调既没有可用会话、也没有携带凭据。
		log.Printf("[plugin] 无可用会话且回调未携带凭据（user=%s run_id=%q），已拒绝", frpUser, runID)
		return nil, false
	}

	userID, ok := service.UserIDFromFrpUser(frpUser)
	if !ok {
		return nil, false
	}
	u, err := h.svc.LoadUser(userID)
	if err != nil {
		return nil, false
	}
	if !service.VerifyClientSecret(u.ClientSecret, got) {
		log.Printf("[plugin] 用户 %s 的凭据复核失败（run_id=%q）", u.Username, runID)
		return nil, false
	}
	if u.Status != model.UserStatusActive {
		return nil, false
	}

	if runID != "" {
		h.svc.Runtime.RecordLogin(runID, u.ID, u.Username)
		// 传空串表示「这些字段本次拿不到」——UpsertClientSession 会
		// 保留登录时记录的真实值，不会把它们抹成空。
		h.UpsertClientSession(u.ID, u.Username, runID, "", "", "", "")
	}
	log.Printf("[plugin] 用户 %s 通过凭据复核补登记会话（run_id=%q）", u.Username, runID)
	return u, true
}

func (h *Handler) onLogin(req *request) response {
	var content loginContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("登录参数解析失败")
	}

	userID, ok := service.UserIDFromFrpUser(content.User)
	if !ok {
		return deny("客户端标识非法，请使用 LiteTunnel 官方客户端")
	}
	u, err := h.svc.LoadUser(userID)
	if err != nil {
		return deny("账号不存在")
	}
	if u.Status != model.UserStatusActive {
		return deny("账号已被禁用，请联系管理员")
	}

	// 每用户独立凭据校验：即使全局 token 泄露，也无法冒充他人身份。
	got := ""
	if content.Metas != nil {
		got = content.Metas[service.MetaTokenKey]
	}
	if !service.VerifyClientSecret(u.ClientSecret, got) {
		log.Printf("[plugin] 用户 %s 登录凭据校验失败，来源 %s", u.Username, content.ClientAddress)
		return deny("客户端凭据无效，请在控制台重新下载客户端配置")
	}

	// 首次登录时 frps **还没有**分配 run_id：它要等本次回调通过之后才生成，
	// 并通过 LoginResp 回给客户端。所以这里 content.RunID 通常是空的。
	//
	// 此刻无法按 run_id 登记会话，但也不能就此静默返回——那正是这个
	// 问题长期查不出来的原因：登录「成功」了，会话表却是空的，而
	// 日志里没有任何线索。会话会由紧接着的 NewProxy 通过凭据复核补登记
	// （见 resolveUser 的第 3 级回落）。
	if content.RunID == "" {
		log.Printf("[plugin] 用户 %s 登录通过（首次登录，frps 尚未分配 run_id，会话将在 NewProxy 阶段补登记）", u.Username)
		return allow()
	}

	h.svc.Runtime.RecordLogin(content.RunID, u.ID, u.Username)
	h.UpsertClientSession(u.ID, u.Username, content.RunID, content.ClientAddress, content.Version, content.Os, content.Arch)
	return allow()
}

func (h *Handler) onNewProxy(req *request) response {
	var content newProxyContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("代理参数解析失败")
	}

	// 传 metas：首次登录时会话尚未登记，需要靠它复核凭据。
	u, ok := h.resolveUser(content.User.User, content.User.RunID, content.User.Metas)
	if !ok {
		return deny("客户端未完成认证，请重启客户端后重试")
	}
	if u.Status != model.UserStatusActive {
		return deny("账号已被禁用")
	}
	if h.svc.Runtime.IsQuotaExceeded(u.ID) {
		return deny("流量额度已用尽，请兑换流量或联系管理员")
	}

	t, err := h.svc.FindTunnelByName(u.ID, content.ProxyName)
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

func domainMatched(t *model.Tunnel, content *newProxyContent) bool {
	if t.Domain != "" {
		for _, d := range content.CustomDomains {
			if strings.EqualFold(d, t.Domain) {
				return true
			}
		}
		return false
	}
	if t.Subdomain != "" {
		return strings.EqualFold(content.SubDomain, t.Subdomain)
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
	}
	return allow()
}

// onNewUserConn 是配额断流的实时拦截点：每次新建用户连接都会经过这里。
// 该路径只做内存查表，不触碰数据库。
func (h *Handler) onNewUserConn(req *request) response {
	var content newUserConnContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return allow()
	}

	// 优先走会话缓存；缓存未命中时才回落数据库。
	if content.User.RunID != "" {
		if s, ok := h.svc.Runtime.LookupSession(content.User.RunID); ok {
			if h.svc.Runtime.IsQuotaExceeded(s.UserID) {
				return deny("流量额度已用尽")
			}
			return allow()
		}
	}
	u, ok := h.resolveUser(content.User.User, content.User.RunID, content.User.Metas)
	if !ok {
		return deny("客户端未完成认证")
	}
	if h.svc.Runtime.IsQuotaExceeded(u.ID) {
		return deny("流量额度已用尽")
	}
	return allow()
}

// ---- 会话落库 ----

// UpsertClientSession 记录/更新一次客户端登录会话。
//
// 只有 onLogin 在凭据校验通过后才会调用本方法，
// 因此该表是后续插件回调判断身份可信度的唯一依据。
func (h *Handler) UpsertClientSession(userID uint, username, runID, addr, version, osName, arch string) {
	if runID == "" {
		return
	}
	now := time.Now()
	s := model.ClientSession{
		UserID:     userID,
		Username:   username,
		RunID:      runID,
		Addr:       addr,
		Version:    version,
		OS:         osName,
		Arch:       arch,
		Online:     true,
		LastSeenAt: now,
	}

	fields := map[string]any{
		"user_id":      userID,
		"username":     username,
		"online":       true,
		"last_seen_at": now,
	}
	// 空值不参与更新。
	//
	// 这个方法有两条调用路径：onLogin（四个字段都有值）与
	// resolveUser 的凭据复核补登记（只有 user / run_id，其余拿不到）。
	// 无脑 Assign 的话，补登记会把登录时记录的真实来源 IP 与版本号
	// 抹成空——而恰好是这两个字段在排查连接问题时最有用。
	if addr != "" {
		fields["addr"] = addr
	}
	if version != "" {
		fields["version"] = version
	}
	if osName != "" {
		fields["os"] = osName
	}
	if arch != "" {
		fields["arch"] = arch
	}

	h.svc.DB.Where("run_id = ?", runID).Assign(fields).FirstOrCreate(&s)
}
