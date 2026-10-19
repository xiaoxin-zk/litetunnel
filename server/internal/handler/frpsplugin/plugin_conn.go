package frpsplugin

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

func (h *Handler) onNewUserConn(req *request) response {
	var content newUserConnContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		log.Printf("[plugin] NewUserConn 请求体解析失败，已拒绝: %v", err)
		return deny("请求格式非法")
	}
	if r, notReady := h.denyUntilGuardReady(); notReady {
		return r
	}

	if content.User.RunID != "" {
		if s, ok := h.svc.Runtime.LookupSession(content.User.RunID); ok {
			if !h.svc.EnsureSessionOnline(content.User.RunID) {
				return deny("会话已失效，请重新连接")
			}
			if blocked, exceeded, ok := h.svc.SessionGuard(content.User.RunID); ok {
				if blocked {
					return deny("账号已被禁用")
				}
				if exceeded {
					return deny("流量额度已用尽")
				}
				return h.allowUserConn(&content)
			}
			blocked, exceeded, ok := h.localAdmission(s.UserID)
			if !ok {
				log.Printf("[plugin] 用户 %d 的准入状态在读取期间持续变化，无法确认是否已禁用，已拒绝新建连接", s.UserID)
				return deny("账号状态正在变更，请稍后重试")
			}
			if blocked {
				return deny("账号已被禁用")
			}
			if exceeded {
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
	blocked, exceeded, ok := h.localAdmission(u.ID)
	if !ok {
		log.Printf("[plugin] 用户 %d 的准入状态在读取期间持续变化，无法确认是否已禁用，已拒绝新建连接", u.ID)
		return deny("账号状态正在变更，请稍后重试")
	}
	if blocked {
		return deny("账号已被禁用")
	}
	if exceeded {
		return deny("流量额度已用尽")
	}
	return h.allowUserConn(&content)
}

func (h *Handler) allowUserConn(c *newUserConnContent) response {
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
