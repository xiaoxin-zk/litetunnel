package frpsplugin

import (
	"encoding/json"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type closeProxyContent struct {
	User      userInfo `json:"user"`
	ProxyName string   `json:"proxy_name"`
}

type pingContent struct {
	User         userInfo `json:"user"`
	PrivilegeKey string   `json:"privilege_key"`
	Timestamp    int64    `json:"timestamp"`
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
		h.svc.RefreshSessionGuard(content.User.RunID)
	}
	return allow()
}

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
