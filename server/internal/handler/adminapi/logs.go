package adminapi

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// ListLoginLogs 查询登录日志。
func (h *Handler) ListLoginLogs(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListLoginLogs(
		c.Query("kind"), c.Query("result"), c.Query("username"), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ListClients 客户端会话列表。
func (h *Handler) ListClients(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListClientSessions(uint(userID), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}

// ListAuditLogs 审计日志。
func (h *Handler) ListAuditLogs(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	list, total, err := h.svc.ListAuditLogs(c.Query("action"), offset, pageSize)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.PageOK(c, list, total, page, pageSize)
}
