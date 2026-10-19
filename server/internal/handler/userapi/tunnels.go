package userapi

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

func (h *Handler) ListTunnels(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	list, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	u, err := h.svc.LoadUser(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	bl := h.svc.EffectiveBandwidth(u)
	out := make([]gin.H, 0, len(list))
	for i := range list {
		out = append(out, h.tunnelVO(&list[i], bl))
	}
	httpx.OK(c, out)
}

func (h *Handler) tunnelVO(t *model.Tunnel, bandwidthLimit int64) gin.H {
	return gin.H{
		"id":                  t.ID,
		"name":                t.Name,
		"type":                t.Type,
		"local_ip":            t.LocalIP,
		"local_port":          t.LocalPort,
		"remote_port":         t.RemotePort,
		"domain":              t.Domain,
		"subdomain":           t.Subdomain,
		"remark":              t.Remark,
		"status":              t.Status,
		"online":              h.svc.IsTunnelOnline(t),
		"traffic_used":        t.TrafficUsed,
		"bandwidth_limit":     bandwidthLimit,
		"bandwidth_limit_str": service.FormatBandwidthHuman(bandwidthLimit),
		"use_encryption":      t.UseEncryption,
		"use_compression":     t.UseCompression,
		"last_online_at":      t.LastOnlineAt,
		"created_at":          t.CreatedAt,
		"public_addr":         h.svc.TunnelPublicAddr(t),
	}
}

func (h *Handler) CreateTunnel(c *gin.Context) {
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.CreateTunnel(u, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t, h.svc.EffectiveBandwidth(u)))
}

func (h *Handler) CreateTunnelsBatch(c *gin.Context) {
	var in service.CreateTunnelBatchInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	res, err := h.svc.CreateTunnelsBatch(u, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}

	created := make([]gin.H, 0, len(res.Created))
	bl := h.svc.EffectiveBandwidth(u)
	for i := range res.Created {
		created = append(created, h.tunnelVO(&res.Created[i], bl))
	}

	httpx.OK(c, gin.H{
		"created":           created,
		"failures":          res.Failures,
		"firewall_failures": res.FirewallFailures,
		"message":           batchMessage(len(created), len(res.Failures), len(res.FirewallFailures)),
	})
}

func batchMessage(ok, failed, fwFailed int) string {
	var base string
	switch {
	case failed == 0:
		base = fmt.Sprintf("已创建 %d 条隧道，公网端口由服务端自动分配", ok)
	case ok == 0:
		base = "没有成功创建任何隧道，请查看失败原因"
	default:
		base = fmt.Sprintf("成功创建 %d 条，%d 条失败，请查看失败原因", ok, failed)
	}
	if fwFailed > 0 {
		base += fmt.Sprintf("；另有 %d 条已创建但防火墙放行未入队，请稍后重试", fwFailed)
	}
	return base
}

func (h *Handler) UpdateTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var in service.TunnelInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	u, err := h.svc.LoadUser(middleware.CurrentUserID(c))
	if err != nil {
		shared.Fail(c, err)
		return
	}
	t, err := h.svc.UpdateTunnel(u, id, in)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, h.tunnelVO(t, h.svc.EffectiveBandwidth(u)))
}

func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	res, err := h.svc.DeleteTunnelResult(middleware.CurrentUserID(c), id)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"message":          "隧道已删除",
		"db_updated":       res.DBUpdated,
		"firewall_pending": res.FirewallPending,
		"warning":          res.Warning,
	})
}

type tunnelStatusReq struct {
	Status string `json:"status" binding:"required"`
}

func (h *Handler) SetTunnelStatus(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	var req tunnelStatusReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	res, err := h.svc.SetTunnelStatusResult(middleware.CurrentUserID(c), id, req.Status)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"message":          "状态已更新",
		"db_updated":       res.DBUpdated,
		"firewall_pending": res.FirewallPending,
		"warning":          res.Warning,
	})
}
