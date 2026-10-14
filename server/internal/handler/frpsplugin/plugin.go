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
func (h *Handler) Handle(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusOK, allow())
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusOK, allow())
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

// resolveUser 依据 frp 的 user / run_id 定位平台账号。
//
// 安全要求：run_id 是**唯一**的身份依据，客户端自报的 user 字段只用于交叉核对。
// 会话必须来自「已通过每用户凭据校验」的来源，否则拒绝。
//
// 回落顺序：
//  1. 内存会话缓存（由 onLogin 在凭据校验通过后写入）；
//  2. 数据库会话表（同样只在凭据校验通过后写入，用于控制面重启后的平滑过渡）。
//
// 绝不能仅凭 frpUser 就查库放行：那等于绕过了 Login 的凭据校验，
// 任何人只要知道目标用户名与全局 token 就能冒充该用户。
func (h *Handler) resolveUser(frpUser, runID string) (*model.User, bool) {
	userID, ok := service.UserIDFromFrpUser(frpUser)
	if !ok || runID == "" {
		return nil, false
	}

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
	sess, err := h.svc.FindTrustedClientSession(runID)
	if err != nil {
		return nil, false
	}
	if sess.UserID != userID {
		log.Printf("[plugin] run_id %s 声明的用户 ID %d 与会话不符（实际 %d），已拒绝",
			runID, userID, sess.UserID)
		return nil, false
	}
	u, err := h.svc.LoadUser(sess.UserID)
	if err != nil {
		return nil, false
	}
	h.svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	return u, true
}

func (h *Handler) onLogin(req *request) response {
	var content loginContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("登录参数解析失败")
	}

	username, ok := service.UsernameFromFrpUser(content.User)
	if !ok {
		return deny("客户端标识非法，请使用 LiteTunnel 官方客户端")
	}
	u, err := h.svc.LoadUserByUsername(username)
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
		log.Printf("[plugin] 用户 %s 登录凭据校验失败，来源 %s", username, content.ClientAddress)
		return deny("客户端凭据无效，请在控制台重新下载客户端配置")
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

	u, ok := h.resolveUser(content.User.User, content.User.RunID)
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

	// 服务端强制限速：以数据库中的限速为准覆盖客户端声明，
	// 并把限速模式固定为 server，客户端改配置也无法绕过。
	changed := false
	want := service.FormatBandwidth(t.BandwidthLimit)
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
	u, ok := h.resolveUser(content.User.User, content.User.RunID)
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
	h.svc.DB.Where("run_id = ?", runID).Assign(map[string]any{
		"user_id":      userID,
		"username":     username,
		"addr":         addr,
		"version":      version,
		"os":           osName,
		"arch":         arch,
		"online":       true,
		"last_seen_at": now,
	}).FirstOrCreate(&s)
}
