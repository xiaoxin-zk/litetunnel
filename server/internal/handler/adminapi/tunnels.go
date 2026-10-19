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
//
// 用结构化变体取回结果：数据库改成功但防火墙规则没跟上时，接口仍应返回
// 成功，但必须把「规则待处理」告诉前端（见 service.TunnelMutationResult）。
// 把它压成一个 error 会让管理员重试并得到「隧道不存在」，以为系统坏了。
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
	res, err := h.svc.AdminSetTunnelStatusResult(id, req.Status)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.status", "tunnel", c.Param("id"), "状态变更为 "+req.Status)
	httpx.OK(c, gin.H{
		"message":          "状态已更新",
		"db_updated":       res.DBUpdated,
		"firewall_pending": res.FirewallPending,
		"warning":          res.Warning,
	})
}

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	res, err := h.svc.AdminDeleteTunnelResult(id)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "tunnel.delete", "tunnel", c.Param("id"), "删除隧道")
	httpx.OK(c, gin.H{
		"message":          "隧道已删除",
		"db_updated":       res.DBUpdated,
		"firewall_pending": res.FirewallPending,
		"warning":          res.Warning,
	})
}
