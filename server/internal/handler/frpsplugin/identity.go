package frpsplugin

import (
	"encoding/json"
	"log"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

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

func (h *Handler) resolveUser(frpUser, runID string, metas map[string]string) (*model.User, bool) {
	userID, ok := service.UserIDFromFrpUser(frpUser)
	if !ok {
		return nil, false
	}

	if runID != "" {
		if s, ok := h.svc.Runtime.LookupSession(runID); ok {
			if s.UserID != userID {
				log.Printf("[plugin] run_id %s 声明的用户 ID %d 与会话不符（实际 %d），已拒绝",
					runID, userID, s.UserID)
				return nil, false
			}
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

		if sess, err := h.svc.FindTrustedClientSession(runID); err == nil {
			if sess.UserID != userID {
				log.Printf("[plugin] run_id %s 声明的用户 ID %d 与会话不符（实际 %d），已拒绝",
					runID, userID, sess.UserID)
				return nil, false
			}
			if u, err := h.svc.LoadUser(sess.UserID); err == nil {
				h.svc.Runtime.RecordLogin(runID, u.ID, u.Username)
				h.svc.PrimeSessionGuard(runID, u)
				return u, true
			}
		}
	}

	return h.authenticateByMeta(frpUser, runID, metas)
}

func (h *Handler) authenticateByMeta(frpUser, runID string, metas map[string]string) (*model.User, bool) {
	got := ""
	if metas != nil {
		got = metas[service.MetaTokenKey]
	}
	if got == "" {
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

	got := ""
	if content.Metas != nil {
		got = content.Metas[service.MetaTokenKey]
	}
	if !service.VerifyClientSecret(u.ClientSecret, got) {
		log.Printf("[plugin] 用户 %s 登录凭据校验失败，来源 %s", u.Username, content.ClientAddress)
		return deny("客户端凭据无效，请在控制台重新下载客户端配置")
	}

	if content.RunID == "" {
		log.Printf("[plugin] 用户 %s 登录通过（首次登录，frps 尚未分配 run_id，会话将在 NewProxy 阶段补登记）", u.Username)
		return allow()
	}

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
