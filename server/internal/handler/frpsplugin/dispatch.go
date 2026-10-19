package frpsplugin

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

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

func allow() response { return response{Unchange: true} }

func deny(reason string) response {
	return response{Reject: true, RejectReason: reason, Unchange: true}
}

func modify(content any) response {
	return response{Unchange: false, Content: content}
}

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
		log.Printf("[plugin] 未知操作 %q，已拒绝（fail-closed）", req.Op)
		res = deny("插件不支持的操作")
	}

	c.JSON(http.StatusOK, res)
}

func (h *Handler) denyUntilGuardReady() (response, bool) {
	if h.svc.Runtime.AccessGuardReady() {
		return response{}, false
	}
	return deny("服务正在加载账号状态，请稍后重试"), true
}

const admissionReadAttempts = 4

func (h *Handler) localAdmission(userID uint) (blocked, exceeded, ok bool) {
	rt := h.svc.Runtime
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
