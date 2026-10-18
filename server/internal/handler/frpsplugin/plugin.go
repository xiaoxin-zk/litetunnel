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

type Handler struct {
	svc        *service.Services
	allowCIDRs []*net.IPNet
	// conns 按隧道限制新建连接速率，并在持续超限时短暂熔断。
	// 纯内存状态：限制针对「此刻正在发生的滥用」，不需要跨实例或跨重启。
	conns *connLimiter
}

// New 构造处理器。allowCIDRs 为允许调用本回调的来源网段。
//
// 解析失败的条目与「白名单为空」都会被记下来：前者会被静默丢弃，后者会让
// Guard 拒绝**所有**回调——表现是「隧道全部起不来」，而单条日志只有一个
// 403。启动校验（config 包）会在更早的地方拦住非法项，这里是兜底与线索。
func New(svc *service.Services, cidrs []string) *Handler {
	h := &Handler{svc: svc, conns: newConnLimiter()}
	var invalid []string
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
			continue
		}
		invalid = append(invalid, c)
	}
	if len(invalid) > 0 {
		log.Printf("[plugin] LT_FRPS_PLUGIN_ALLOW_CIDR 中有 %d 项不是合法的 IP 或 CIDR: %v",
			len(invalid), invalid)
	}
	if len(h.allowCIDRs) == 0 {
		log.Printf("[plugin] 插件回调白名单为空：所有回调都会被拒绝，隧道将无法上线")
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
		// 未知操作一律拒绝，与本函数开头写的 fail-closed 策略保持一致。
		//
		// 这里曾经是 allow()：一个空 op、或 frps 升级后新增的操作，都会
		// 静默走放行分支。而「放行」在插件语义里等于**跳过鉴权**——
		// 攻击者只要构造出我们不认识的操作名，就能拿到与「凭据校验通过」
		// 相同的效果。
		//
		// 代价是 frp 协议新增操作时会出现显式故障（登录/建代理被拒），
		// 但那正是我们想要的：显式故障立刻暴露，静默放行没人会知道。
		log.Printf("[plugin] 未知操作 %q，已拒绝（fail-closed）", req.Op)
		res = deny("插件不支持的操作")
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
			// 内存命中不等于会话仍有效：撤销发生在哪台实例上是随机的，
			// 本机缓存的会话要按短 TTL 与数据库核对一次（见 EnsureSessionOnline）。
			if !h.svc.EnsureSessionOnline(runID) {
				log.Printf("[plugin] run_id %s 的会话已在其他实例撤销，已拒绝", runID)
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
				// 回填会话时顺手初始化准入快照：否则在收到下一次 Ping 之前，
				// 这台实例只能靠本机的配额缓存判断，多副本时可能已经落后。
				h.svc.PrimeSessionGuard(runID, u)
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
		// 先落库、再登记内存会话：写库失败时不能把会话记成可信——后续 Ping 的
		// 准入刷新会因为「查不到可信会话」把它永久拒绝，而缓存命中路径不会
		// 重新写库，数据库恢复也救不回来。不登记的话，下一次连接会重新走
		// 这条凭据复核路径，天然重试。
		// 传空串表示「这些字段本次拿不到」——UpsertClientSession 会
		// 保留登录时记录的真实值，不会把它们抹成空。
		if err := h.UpsertClientSession(u.ID, u.Username, runID, "", "", "", ""); err != nil {
			log.Printf("[plugin] 用户 %s 的会话未能落库（run_id=%q），本次不登记内存会话，下次连接重试",
				u.Username, runID)
		} else {
			h.svc.Runtime.RecordLogin(runID, u.ID, u.Username)
			h.svc.PrimeSessionGuard(runID, u)
			log.Printf("[plugin] 用户 %s 通过凭据复核补登记会话（run_id=%q）", u.Username, runID)
		}
	}
	return u, true
}

func (h *Handler) onLogin(req *request) response {
	var content loginContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("登录参数解析失败")
	}
	if r, notReady := h.denyUntilGuardReady(); notReady {
		return r
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

	// 同样先落库、再登记内存会话（理由见 resolveUser 的补登记分支）。
	if err := h.UpsertClientSession(u.ID, u.Username, content.RunID,
		content.ClientAddress, content.Version, content.Os, content.Arch); err != nil {
		log.Printf("[plugin] 用户 %s 的登录会话未能落库（run_id=%q），本次不登记内存会话，下次连接重试",
			u.Username, content.RunID)
		return allow()
	}
	h.svc.Runtime.RecordLogin(content.RunID, u.ID, u.Username)
	h.svc.PrimeSessionGuard(content.RunID, u)
	return allow()
}

// denyUntilGuardReady 在准入状态（超额与禁用标记）尚未加载完成时给出拒绝响应。
//
// 这条判断必须出现在每一个「放行」的入口上（登录、建代理、新建用户连接），
// 且方向是拒绝而不是放行：此时内存里既没有超额标记也没有禁用标记，
// 「查不到」与「没超额」在数据结构上完全一样。控制面刚启动、或数据库一度
// 不可用之后就是这种状态，而那一刻恰恰所有客户端都在重连——按放行处理，
// 等于在最该拦截的时候把超额与已禁用的账号全部放进来。
//
// 状态只在整表加载成功后置位（见 service.LoadAccessGuard），所以这里的拒绝
// 是短暂的：数据库恢复后采集协程会把它翻回来，不需要人工干预。
func (h *Handler) denyUntilGuardReady() (response, bool) {
	if h.svc.Runtime.AccessGuardReady() {
		return response{}, false
	}
	// 不在热路径打日志：数据库长时间不可用时，每个连接都会走到这里，
	// 刷屏只会淹没真正的原因。加载失败本身在 service 侧已经记过了。
	return deny("服务正在加载账号状态，请稍后重试"), true
}

// ---- 会话落库 ----

// UpsertClientSession 记录/更新一次客户端登录会话，返回写库是否成功。
//
// 只有 onLogin 在凭据校验通过后才会调用本方法，
// 因此该表是后续插件回调判断身份可信度的唯一依据。
//
// 返回错误必须被调用方处理：写库失败却把会话登记进内存的话，这个会话会被
// 后续 Ping 的准入刷新判为「查不到可信会话」而**永久**拒绝——而缓存命中
// 路径不会重新执行会话写入，数据库恢复也救不回来。
func (h *Handler) UpsertClientSession(userID uint, username, runID, addr, version, osName, arch string) error {
	if runID == "" {
		return nil
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

	if err := h.svc.DB.Where("run_id = ?", runID).Assign(fields).FirstOrCreate(&s).Error; err != nil {
		log.Printf("[plugin] 写入客户端会话失败（run_id=%s）: %v", runID, err)
		return err
	}
	return nil
}
