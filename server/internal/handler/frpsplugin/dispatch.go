package frpsplugin

// 请求分发与协议编解码。
//
// 本文件只负责「把一次 HTTP 回调翻译成某个具体处理函数」，以及
// request / response 两个协议结构与 allow / deny / modify 三个响应助手。
//
// 分工（本包按职责分文件，见 package 文档）：
//
//	plugin.go        Handler 结构、构造、来源网段守卫
//	dispatch.go      本文件：协议结构、op 路由、fail-closed 策略
//	identity.go      身份解析与凭据校验（resolveUser / authenticateByMeta / Login）
//	session.go       会话登记与准入快照（UpsertClientSession / Ping / CloseProxy）
//	plugin_proxy.go  代理准入（NewProxy）
//	plugin_conn.go   用户连接准入（NewUserConn）
//
// 把这四处分开是为了让「谁能进来」这个问题的答案只出现在一处：
// 改动准入判断时不需要在几百行回调代码里翻找。

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
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

// admissionReadAttempts 是「读一次可信的本机准入标记」的最大重试次数。
//
// 取 4：正常情况下第一次就稳定（管理操作只在管理员点按钮时发生），
// 连续多次撞上版本变化说明此刻正有一次批量状态变更在进行，与其继续
// 空转，不如直接按「无法确认」拒绝，让客户端下次重连。
const admissionReadAttempts = 4

// localAdmission 读取本机内存里的禁用/超额标记，并保证这份读取不是
// 「读了一半」的撕裂快照。ok=false 表示无法给出可信判定，调用方必须拒绝。
//
// # 为什么需要它
//
// 两个标记（blocked / exceeded）是**分开的两个 map 条目**，由管理路径
// 分两次写入（先 Runtime.BumpGuardVer，再 SetUserBlocked / SetQuotaExceeded）。
// 直接连着读两个条目会读到中间态：版本号已经推进、禁用标记还没落下，
// 于是「刚被禁用的账号」在这一瞬间看起来是正常的。这类撕裂窗口在单次
// 管理操作里只有几条语句的距离，但它恰好落在「所有客户端正在重连」的
// 时刻就会被撞上——而它一旦放行，后果是代理注册成功。
//
// 所以这里用准入版本号把读取包起来：读之前取一次 GuardVer，读完之后再取
// 一次，两次相同才认为这次读到的是同一个稳定版本下的快照。版本变了就重读
// （管理操作通常紧接着就写完了标记），重试用尽仍不稳定则返回 ok=false。
//
// # 它挡不住什么（必须说清）
//
// GuardVer 是**本进程**的版本号，看不到别的实例上发生的禁用。跨实例收敛
// 靠的是会话准入快照（service.SessionGuard / RefreshSessionGuard，随 Ping
// 周期刷新），那条路径在调用本函数之前已经查过了。本函数只负责「本机这份
// 内存标记有没有读干净」，不假装能提供跨实例的实时性。
//
// 另外，管理路径是「先推进版本、再写标记」，所以推进之后、标记落下之前
// 读到的一致性快照里仍然是旧标记。这个窗口无法在读取侧消除（要让读取方
// 看见未来的写，只能加锁或改成单次原子写，那属于 service 侧的结构改动）。
// 这里的定位是**缩小窗口并显式拒绝不确定的情况**，而不是假装竞态不存在。
func (h *Handler) localAdmission(userID uint) (blocked, exceeded, ok bool) {
	rt := h.svc.Runtime
	// 整表快照没加载过时，两个 map 都是空的，「查不到」与「没禁用」同义。
	// 这个判断放在最前面：否则下面的版本比对会在一个空表上「成功」，
	// 得到一份看起来可信、实际上什么都没加载的判定。
	if !rt.AccessGuardReady() {
		return false, false, false
	}
	for i := 0; i < admissionReadAttempts; i++ {
		before := rt.GuardVer()
		blocked = rt.IsUserBlocked(userID)
		exceeded = rt.IsQuotaExceeded(userID)
		if rt.GuardVer() == before {
			return blocked, exceeded, true
		}
	}
	return false, false, false
}
