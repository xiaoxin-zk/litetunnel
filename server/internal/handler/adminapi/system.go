package adminapi

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/monitor"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// CheckUpdate 查询最新发布版本，force=1 时绕过缓存。
func (h *Handler) CheckUpdate(c *gin.Context) {
	status, err := h.svc.CheckUpdate(c.Request.Context(), c.Query("force") == "1")
	if err != nil {
		httpx.Fail(c, http.StatusBadGateway, err.Error())
		return
	}
	httpx.OK(c, status)
}

// ApplyUpdate 下载并替换面板二进制，重启后生效。
func (h *Handler) ApplyUpdate(c *gin.Context) {
	version, err := h.svc.ApplyPanelUpdate(c.Request.Context())
	if err != nil {
		httpx.Fail(c, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(c, "system.update.apply", "system", "", "下载并替换面板二进制："+version)
	httpx.OK(c, gin.H{"applied": true, "version": version, "message": "新版本已就绪，重启后生效"})
}

// RestartPanel 让新二进制接管进程。
func (h *Handler) RestartPanel(c *gin.Context) {
	h.audit(c, "system.update.restart", "system", "", "重启面板使新版本生效")
	httpx.OK(c, gin.H{"restarting": true, "message": "正在重启"})
	h.svc.RestartPanel()
}

func (h *Handler) StatsOverview(c *gin.Context) {
	var (
		userTotal    int64
		userActive   int64
		tunnelTotal  int64
		tunnelActive int64
		onlineClient int64
	)
	db := h.svc.DB

	var totalUsed int64
	queries := []struct {
		name string
		run  func() error
	}{
		{"总用户数", func() error {
			return db.Model(&model.User{}).Count(&userTotal).Error
		}},
		{"活跃用户数", func() error {
			return db.Model(&model.User{}).
				Where("status = ?", model.UserStatusActive).Count(&userActive).Error
		}},
		{"隧道总数", func() error {
			return db.Model(&model.Tunnel{}).Count(&tunnelTotal).Error
		}},
		{"活跃隧道数", func() error {
			return db.Model(&model.Tunnel{}).
				Where("status = ?", model.TunnelStatusActive).Count(&tunnelActive).Error
		}},
		{"在线客户端数", func() error {
			return db.Model(&model.ClientSession{}).
				Where("online = ?", true).Count(&onlineClient).Error
		}},
		{"总流量", func() error {
			var row struct{ Total int64 }
			if err := db.Model(&model.User{}).
				Select("COALESCE(SUM(traffic_used),0) AS total").Scan(&row).Error; err != nil {
				return err
			}
			totalUsed = row.Total
			return nil
		}},
	}
	for _, q := range queries {
		if err := q.run(); err != nil {
			log.Printf("[admin] 首页统计查询失败（%s）: %v", q.name, err)
			shared.Fail(c, err)
			return
		}
	}

	httpx.OK(c, gin.H{
		"user_total":         userTotal,
		"user_active":        userActive,
		"tunnel_total":       tunnelTotal,
		"tunnel_active":      tunnelActive,
		"online_client":      onlineClient,
		"traffic_used_total": totalUsed,
	})
}

func (h *Handler) SystemMetrics(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))

	col := h.svc.Monitor
	httpx.OK(c, gin.H{
		"latest":          col.Latest(),
		"series":          col.Series(limit),
		"sample_interval": int(monitor.SampleInterval.Seconds()),
		"max_samples":     monitor.MaxSamples,
		"recovery":        h.svc.RecoveryStats(),
		"audit":           h.svc.AuditHealth(),
		"drain_fallback":  h.svc.ProxyDrainFallback(),
		"drain_race":      h.svc.ProxyDrainRaceHealth(),
		"drain_queue":     h.svc.ProxyDrainQueueHealth(),
	})
}

func (h *Handler) ListClientPackages(c *gin.Context) {
	list, err := h.svc.ListClientPackages()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"files":        list,
		"download_url": strings.TrimSpace(h.svc.Settings.Get(service.KeySiteClientDownloadURL)),
		"dist_dir":     h.svc.Cfg.ClientDistDir,
		"max_size":     service.MaxClientPackageSize,
		"uploadable":   true,
	})
}

func (h *Handler) UploadClientPackage(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		httpx.BadRequest(c, "请选择要上传的文件")
		return
	}
	name, err := service.SanitizeClientFileName(file.Filename)
	if err != nil {
		shared.Fail(c, err)
		return
	}

	src, err := file.Open()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	defer func() { _ = src.Close() }()

	n, err := h.svc.SaveClientPackage(name, src)
	if err != nil {
		shared.Fail(c, err)
		return
	}

	h.audit(c, "client.upload", "client_dist", name,
		fmt.Sprintf("上传客户端安装包 %s（%d 字节）", name, n))
	httpx.OK(c, gin.H{
		"message": "上传成功",
		"name":    name,
		"size":    n,
	})
}

func (h *Handler) DeleteClientPackage(c *gin.Context) {
	name := c.Param("name")
	if err := h.svc.DeleteClientPackage(name); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "client.delete", "client_dist", name, "删除客户端安装包 "+name)
	httpx.OK(c, gin.H{"message": "已删除"})
}

func (h *Handler) FirewallStatus(c *gin.Context) {
	httpx.OK(c, gin.H{
		"firewall": h.svc.FirewallStatusOf(),
		"pool":     h.svc.PortPoolUsageOf(),
	})
}

type firewallPortReq struct {
	Port  int    `json:"port" binding:"required"`
	Proto string `json:"proto"`
}

func (h *Handler) FirewallOpenPort(c *gin.Context) {
	var req firewallPortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写端口号")
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	if err := h.svc.FirewallManualOpen(req.Port, req.Proto); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "firewall.open", "firewall", strconv.Itoa(req.Port),
		fmt.Sprintf("放行 %d/%s", req.Port, req.Proto))
	httpx.OK(c, gin.H{"message": "端口已放行"})
}

func (h *Handler) FirewallClosePort(c *gin.Context) {
	var req firewallPortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写端口号")
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	if err := h.svc.FirewallManualClose(req.Port, req.Proto); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "firewall.close", "firewall", strconv.Itoa(req.Port),
		fmt.Sprintf("关闭 %d/%s", req.Port, req.Proto))
	httpx.OK(c, gin.H{"message": "端口已关闭"})
}

func (h *Handler) FirewallClearFailed(c *gin.Context) {
	var req firewallPortReq
	if err := c.ShouldBindJSON(&req); err != nil || req.Port <= 0 {
		httpx.BadRequest(c, "请填写端口号")
		return
	}
	if err := h.svc.ClearFirewallFailed(req.Port); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "firewall.clear_failed", "firewall", strconv.Itoa(req.Port),
		fmt.Sprintf("清除已终止的失败记录（端口 %d）", req.Port))
	httpx.OK(c, gin.H{"message": "记录已清除"})
}

func (h *Handler) FirewallRescan(c *gin.Context) {
	httpx.OK(c, gin.H{
		"firewall": h.svc.FirewallStatusOf(),
		"pool":     h.svc.PortPoolUsageOf(),
	})
}
