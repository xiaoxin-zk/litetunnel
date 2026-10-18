package frpsplugin

// 用户连接准入：frps 每接受一个用户连接就回调一次 NewUserConn。
//
// 这条路径在热路径上（每次连接一次），只做内存查表与计数，
// 不触碰数据库；准入策略（封禁 / 超额 / 速率）集中在这里。

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type newUserConnContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	RemoteAddr string   `json:"remote_addr"`
}

// onNewUserConn 是配额断流的实时拦截点：每次新建用户连接都会经过这里。
// 该路径只做内存查表，不触碰数据库。
func (h *Handler) onNewUserConn(req *request) response {
	var content newUserConnContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		// 解析失败不能放行。这里是配额与封禁的实时拦截点，
		// 读不懂身份就无法判断该不该拦，而「放行」等于跳过拦截——
		// 与未知操作的处理保持一致（fail-closed）。
		log.Printf("[plugin] NewUserConn 请求体解析失败，已拒绝: %v", err)
		return deny("请求格式非法")
	}
	if r, notReady := h.denyUntilGuardReady(); notReady {
		return r
	}

	// 优先走会话缓存；缓存未命中时才回落数据库。
	if content.User.RunID != "" {
		if s, ok := h.svc.Runtime.LookupSession(content.User.RunID); ok {
			// 会话可能已被**别的实例**撤销（改密、重置密码、轮换 client secret）：
			// 撤销方只清自己的内存会话，并把数据库里的会话置为离线；本机的
			// 内存会话不会消失，缓存在这里就直接放行了。按短 TTL 回查一次，
			// 让撤销在几秒内生效，而不是等下一个 Ping 周期刷到准入快照。
			if !h.svc.EnsureSessionOnline(content.User.RunID) {
				return deny("会话已失效，请重新连接")
			}
			// 两个标记都要看，缺一不可：
			//   - blocked：账号被禁用/封禁；
			//   - exceeded：流量用超了。
			// 曾经只看超额，而禁用又是靠把超额强制置 true 实现的，
			// 于是每轮流量采集都会把禁用用户的超额标记按配额重算回去，
			// 配额没超限的禁用账号就重新被放行了。
			//
			// 会话里有一份按 Ping 周期刷新的快照：多副本时账号可能在别的实例
			// 被禁用，本地内存标记要等重启才会变，而快照最多落后一个 Ping 周期。
			// 与代理注册路径共用同一份判断（见 SessionGuard），避免两边结论不一致。
			if blocked, exceeded, ok := h.svc.SessionGuard(content.User.RunID); ok {
				if blocked {
					return deny("账号已被禁用")
				}
				if exceeded {
					return deny("流量额度已用尽")
				}
				return h.allowUserConn(&content)
			}
			if h.svc.Runtime.IsUserBlocked(s.UserID) {
				return deny("账号已被禁用")
			}
			if h.svc.Runtime.IsQuotaExceeded(s.UserID) {
				return deny("流量额度已用尽")
			}
			return h.allowUserConn(&content)
		}
	}
	u, ok := h.resolveUser(content.User.User, content.User.RunID, content.User.Metas)
	if !ok {
		return deny("客户端未完成认证")
	}
	if u.Status != model.UserStatusActive {
		return deny("账号已被禁用")
	}
	if h.svc.Runtime.IsUserBlocked(u.ID) {
		return deny("账号已被禁用")
	}
	if h.svc.Runtime.IsQuotaExceeded(u.ID) {
		return deny("流量额度已用尽")
	}
	return h.allowUserConn(&content)
}

// allowUserConn 在身份与配额都通过后，再做一次连接速率限制。
//
// 放在最后而不是最前：账号被禁用、额度用尽这类原因更具体，
// 先报它们用户才知道该找谁；速率限制只是「看起来像滥用」时的兜底。
func (h *Handler) allowUserConn(c *newUserConnContent) response {
	// 网站类隧道由 vhost 承接，连接数与页面请求数同阶，正常浏览就可能
	// 触发按「新建连接」的限流，因此不在这里限制。
	switch strings.ToLower(strings.TrimSpace(c.ProxyType)) {
	case "http", "https", "tcpmux":
		return allow()
	}
	key := c.User.RunID + "|" + c.ProxyName
	if ok, wait := h.conns.allow(key); !ok {
		return deny(fmt.Sprintf("连接过于频繁，已临时限制（约 %s 后恢复）", wait.Round(time.Second)))
	}
	return allow()
}
