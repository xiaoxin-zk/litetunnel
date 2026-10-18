package frpsplugin

// 身份解析与凭据校验。
//
// 本文件回答一个问题：**这次回调声称的操作者是谁，凭什么相信它**。
// 它不负责「这个身份现在能不能建代理/建连接」——那是准入判断，见
// plugin_proxy.go 与 plugin_conn.go，两者都以这里的输出为前提。
//
// 分三层回落（见 resolveUser 的说明）：内存会话 → 数据库会话 → 每用户凭据复核。
// 第三层不是「信任 frp 传来的 user 字段」，而是校验同一份 per-user secret，
// 强度与 Login 完全一致。

import (
	"encoding/json"
	"log"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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
