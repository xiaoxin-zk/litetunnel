package adminapi

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// ListTunnels 全部隧道。
func (h *Handler) ListTunnels(c *gin.Context) {
	page, pageSize, offset := httpx.Pagination(c)
	userID, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	list, total, err := h.svc.ListAllTunnels(
		c.Query("keyword"), c.Query("status"), uint(userID), offset, pageSize,
	)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, gin.H{
			"id":           list[i].ID,
			"user_id":      list[i].UserID,
			"name":         list[i].Name,
			"type":         list[i].Type,
			"local_ip":     list[i].LocalIP,
			"local_port":   list[i].LocalPort,
			"remote_port":  list[i].RemotePort,
			"domain":       list[i].Domain,
			"subdomain":    list[i].Subdomain,
			"status":       list[i].Status,
			"online":       h.svc.IsTunnelOnline(&list[i]),
			"traffic_used": list[i].TrafficUsed,
			"created_at":   list[i].CreatedAt,
		})
	}
	httpx.PageOK(c, out, total, page, pageSize)
}

// SetTunnelStatus 启用/停用隧道。
func (h *Handler) SetTunnelStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var req statusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if err := h.svc.AdminSetTunnelStatus(id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.status", "tunnel", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{"message": "状态已更新"})
}

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	if err := h.svc.AdminDeleteTunnel(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.delete", "tunnel", c.Param("id"), "删除隧道")
	httpx.OK(c, gin.H{"message": "隧道已删除"})
}
