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

// ListTunnels 列出当前用户隧道，并附加运行态。
func (h *Handler) ListTunnels(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	list, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	// 限速来自分组，与隧道条数无关，因此只解析一次。
	// LoadUser 已预加载 Group，这里不会产生额外查询。
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

// tunnelVO 组装单条隧道的返回结构。
//
// bandwidthLimit 由调用方传入，而不是读 t.BandwidthLimit：
// 那是建隧道时的快照，可能已经与分组当前值不一致。
// 由调用方统一解析一次（同一个用户的所有隧道限速必然相同），
// 既保证与强制下发的值同源，也避免每条隧道各查一次库。
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
		// 地址由 service 统一计算：HTTP 与 HTTPS 的入口不是同一条，
		// 而这两条规则必须在客户端、用户控制台、管理端之间完全一致。
		"public_addr": h.svc.TunnelPublicAddr(t),
	}
}

// CreateTunnel 新建隧道。
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

// CreateTunnelsBatch 批量创建隧道。
//
// 与单条创建共用同一套服务层校验与端口分配逻辑，只是逐条循环、
// 把每条的结果分别收上来——不整体回滚，见 CreateTunnelsBatch 的说明。
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

	// 返回体里带上已建隧道的完整视图，客户端可以直接渲染列表，
	// 不需要再为每条隧道单独请求一次。
	created := make([]gin.H, 0, len(res.Created))
	bl := h.svc.EffectiveBandwidth(u)
	for i := range res.Created {
		created = append(created, h.tunnelVO(&res.Created[i], bl))
	}

	httpx.OK(c, gin.H{
		"created":  created,
		"failures": res.Failures,
		"message":  batchMessage(len(created), len(res.Failures)),
	})
}

// batchMessage 生成一句人话总结。
//
// 全部成功、部分失败、全部失败三种情况应当给出不同的措辞——
// 让用户只看到「创建完成」而漏掉失败的那几条，是最容易积累
// 「怎么少了几条」这类困惑的地方。
func batchMessage(ok, failed int) string {
	switch {
	case failed == 0:
		return fmt.Sprintf("已创建 %d 条隧道，公网端口由服务端自动分配", ok)
	case ok == 0:
		return "没有成功创建任何隧道，请查看失败原因"
	default:
		return fmt.Sprintf("成功创建 %d 条，%d 条失败，请查看失败原因", ok, failed)
	}
}

// UpdateTunnel 修改隧道。
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

// DeleteTunnel 删除隧道。
func (h *Handler) DeleteTunnel(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "隧道 ID 非法")
		return
	}
	if err := h.svc.DeleteTunnel(middleware.CurrentUserID(c), id); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "隧道已删除"})
}

type tunnelStatusReq struct {
	Status string `json:"status" binding:"required"`
}

// SetTunnelStatus 启用或停用隧道。
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
	if err := h.svc.SetTunnelStatus(middleware.CurrentUserID(c), id, req.Status); err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"message": "状态已更新"})
}
