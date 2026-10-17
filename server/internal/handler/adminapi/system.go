package adminapi

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/monitor"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// StatsOverview 后台首页概览。
func (h *Handler) StatsOverview(c *gin.Context) {
	var (
		userTotal    int64
		userActive   int64
		tunnelTotal  int64
		tunnelActive int64
		onlineClient int64
	)
	db := h.svc.DB

	// 每一项都要确认成功。
	//
	// 以前只检查第一个查询，后面几项忽略错误——查询失败时那几个数字会是 0，
	// 而 0 在首页上**看起来完全正常**：管理员会以为「真的没有在线客户端」，
	// 而不是「数据库出了问题」。把失败当成真实的零值，比直接报错更危险。
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
			// 带上是哪一项失败：日志里只有一条 SQL 错误时，
			// 排查的人还得自己猜是哪块统计出了问题。
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

// SystemMetrics 返回服务器实时指标与最近的采样序列。
//
// latest 与 series 一起返回而不是分两个接口：面板每 5 秒刷新一次，
// 分两次请求会出现「卡片是新值、图表是旧值」这种对不上的瞬间。
func (h *Handler) SystemMetrics(c *gin.Context) {
	// limit 控制返回多少个采样点。0 表示全部（最多由采集器的环形缓冲决定）。
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))

	col := h.svc.Monitor
	httpx.OK(c, gin.H{
		"latest": col.Latest(),
		"series": col.Series(limit),
		// 一并下发采样间隔，让前端自己算出「这批数据覆盖多长时间」，
		// 不需要在前端再硬编码一份——两处写死迟早会不一致。
		"sample_interval": int(monitor.SampleInterval.Seconds()),
		"max_samples":     monitor.MaxSamples,
		"recovery":        h.svc.RecoveryStats(),
	})
}

// ListClientPackages 列出已分发的客户端安装包。
//
// 路径用 client-packages 而不是 clients：后者已经被「在线客户端会话」
// 占用，两个概念完全不同（一个是会话，一个是安装包）。
func (h *Handler) ListClientPackages(c *gin.Context) {
	list, err := h.svc.ListClientPackages()
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{
		"files": list,
		// 一并下发两种分发方式的当前状态，管理端才能告诉管理员
		// 「用户现在实际会从哪里拿到客户端」。
		"download_url": strings.TrimSpace(h.svc.Settings.Get(service.KeySiteClientDownloadURL)),
		"dist_dir":     h.svc.Cfg.ClientDistDir,
		"max_size":     service.MaxClientPackageSize,
		"uploadable":   true,
	})
}

// UploadClientPackage 上传客户端安装包。
//
// 仅超管可用：上传的文件会被分发给**所有用户**下载。
func (h *Handler) UploadClientPackage(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		httpx.BadRequest(c, "请选择要上传的文件")
		return
	}
	// 文件名校验必须在打开文件之前完成：它来自客户端，是不可信输入。
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

// DeleteClientPackage 删除客户端安装包。
func (h *Handler) DeleteClientPackage(c *gin.Context) {
	name := c.Param("name")
	if err := h.svc.DeleteClientPackage(name); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "client.delete", "client_dist", name, "删除客户端安装包 "+name)
	httpx.OK(c, gin.H{"message": "已删除"})
}

// FirewallStatus 返回防火墙运行态与端口池使用情况。
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

// FirewallOpenPort 手工放行一个端口。
func (h *Handler) FirewallOpenPort(c *gin.Context) {
	var req firewallPortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写端口号")
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	// 走手工路径：必须真的放行，不能像自动放行那样「开关没开就静默跳过」。
	if err := h.svc.FirewallManualOpen(req.Port, req.Proto); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "firewall.open", "firewall", strconv.Itoa(req.Port),
		fmt.Sprintf("放行 %d/%s", req.Port, req.Proto))
	httpx.OK(c, gin.H{"message": "端口已放行"})
}

// FirewallClosePort 手工关闭一个端口。
func (h *Handler) FirewallClosePort(c *gin.Context) {
	var req firewallPortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "请填写端口号")
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	// 走手工路径：护栏（保护端口、池外端口）在服务层内校验。
	if err := h.svc.FirewallManualClose(req.Port, req.Proto); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "firewall.close", "firewall", strconv.Itoa(req.Port),
		fmt.Sprintf("关闭 %d/%s", req.Port, req.Proto))
	httpx.OK(c, gin.H{"message": "端口已关闭"})
}

// FirewallClearFailed 清除一条重试已终止的失败记录。
//
// 语义是「管理员已经人工处理完了，不再需要界面提醒」，而不是「再试一次」：
// 后台对终态记录不再自动重试，修好宿主机后想让它补做，用上面的
// 手工放行/关闭，或重新触发一次隧道状态变更。
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

// FirewallRescan 重新扫描端口占用并输出可用区间，供管理页刷新用。
func (h *Handler) FirewallRescan(c *gin.Context) {
	httpx.OK(c, gin.H{
		"firewall": h.svc.FirewallStatusOf(),
		"pool":     h.svc.PortPoolUsageOf(),
	})
}
