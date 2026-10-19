package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// GetAlertSettings 返回告警阈值。Webhook 属于密钥（地址里通常带 access token），
// 已配置时只返回占位符，前端回传占位符表示「保持原值」。
func (h *Handler) GetAlertSettings(c *gin.Context) {
	cfg := h.svc.AlertConfig()
	webhook := cfg.WebhookURL
	configured := webhook != ""
	if configured {
		webhook = service.SecretMask
	}
	httpx.OK(c, gin.H{
		"enabled":            cfg.Enabled,
		"webhook_url":        webhook,
		"webhook_configured": configured,
		"error_rate_pct":     cfg.ErrorRatePct,
		"disk_pct":           cfg.DiskPct,
		"backup_stale_hours": cfg.BackupStaleHr,
		"min_requests":       service.AlertMinRequests,
		"interval_minutes":   service.AlertIntervalMinutes,
		"cooldown_minutes":   service.AlertCooldownMinutes,
		"sample_keep_days":   service.AlertSampleKeepDays,
		"event_keep_days":    service.AlertEventKeepDays,
	})
}

type alertSettingsReq struct {
	Enabled         bool    `json:"enabled"`
	WebhookURL      string  `json:"webhook_url"`
	ErrorRatePct    float64 `json:"error_rate_pct"`
	DiskPct         float64 `json:"disk_pct"`
	BackupStaleHour int     `json:"backup_stale_hours"`
}

func (h *Handler) UpdateAlertSettings(c *gin.Context) {
	var req alertSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}
	if req.WebhookURL == service.SecretMask {
		req.WebhookURL = h.svc.AlertConfig().WebhookURL
	}
	in := map[service.SettingKey]string{
		service.KeyAlertEnabled:     strconv.FormatBool(req.Enabled),
		service.KeyAlertWebhook:     strings.TrimSpace(req.WebhookURL),
		service.KeyAlertErrorRate:   strconv.Itoa(int(req.ErrorRatePct)),
		service.KeyAlertDisk:        strconv.Itoa(int(req.DiskPct)),
		service.KeyAlertBackupHours: strconv.Itoa(req.BackupStaleHour),
	}
	if err := h.svc.UpdateSettings(in); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "alert.settings.update", "alert", "",
		fmt.Sprintf("更新告警设置（启用=%v，错误率阈值=%.0f%%，磁盘阈值=%.0f%%，备份超时=%d 小时）",
			req.Enabled, req.ErrorRatePct, req.DiskPct, req.BackupStaleHour))
	httpx.OK(c, gin.H{"message": "已保存，配置即时生效"})
}

// TestAlertWebhook 用一条测试消息验证地址可达，不写入告警历史，也不占用冷却窗口。
func (h *Handler) TestAlertWebhook(c *gin.Context) {
	if err := h.svc.TestAlertWebhook(); err != nil {
		if errors.Is(err, service.ErrInvalidParam) {
			shared.Fail(c, err)
			return
		}
		h.audit(c, "alert.settings.test_failed", "alert", "", err.Error())
		httpx.Fail(c, http.StatusBadGateway, "推送失败："+err.Error())
		return
	}
	h.audit(c, "alert.settings.test", "alert", "", "发送告警 Webhook 测试消息")
	httpx.OK(c, gin.H{"message": "测试消息已推送，请检查接收端"})
}

func (h *Handler) ListAlertEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))
	list, err := h.svc.ListAlertEvents(limit)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"events": list})
}

func (h *Handler) ListMetricSamples(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))
	list, err := h.svc.ListMetricSamples(limit)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, gin.H{"samples": list})
}
