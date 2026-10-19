package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/outbound"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// GetAlertSettings 返回告警阈值。Webhook 属于密钥（地址里通常带 access token），
// 已配置时只返回占位符，前端回传占位符表示「保持原值」。
func (h *Handler) GetAlertSettings(c *gin.Context) {
	cfg := h.svc.AlertConfig()
	webhook := cfg.WebhookURL
	configured := webhook != ""
	// 只回显主机名：管理员能确认填的是哪个接收端，又不会把路径里的 token 带到浏览器。
	host := ""
	if configured {
		if u, err := url.Parse(webhook); err == nil {
			host = u.Host
		}
		webhook = service.SecretMask
	}
	silenceUntil := ""
	if !cfg.SilenceUntil.IsZero() {
		silenceUntil = cfg.SilenceUntil.Format(time.RFC3339)
	}
	httpx.OK(c, gin.H{
		"enabled":            cfg.Enabled,
		"webhook_url":        webhook,
		"webhook_configured": configured,
		"webhook_host":       host,
		"error_rate_pct":     cfg.ErrorRatePct,
		"disk_pct":           cfg.DiskPct,
		"backup_stale_hours": cfg.BackupStaleHr,
		"sustained_windows":  cfg.SustainedWindows,
		"silence_until":      silenceUntil,
		"silence_reason":     cfg.SilenceReason,
		"silenced":           cfg.Silenced(time.Now()),
		"min_requests":       service.AlertMinRequests,
		"interval_minutes":   service.AlertIntervalMinutes,
		"cooldown_minutes":   service.AlertCooldownMinutes,
		"sample_keep_days":   service.AlertSampleKeepDays,
		"event_keep_days":    service.AlertEventKeepDays,
	})
}

// 字段都用指针：只更新请求里真的出现的项。
// 用零值兜底会让「只想改阈值」的调用顺手把告警关掉。
type alertSettingsReq struct {
	Enabled          *bool    `json:"enabled"`
	WebhookURL       *string  `json:"webhook_url"`
	ErrorRatePct     *float64 `json:"error_rate_pct"`
	DiskPct          *float64 `json:"disk_pct"`
	BackupStaleHour  *int     `json:"backup_stale_hours"`
	SustainedWindows *int     `json:"sustained_windows"`
	SilenceUntil     *string  `json:"silence_until"`
	SilenceReason    *string  `json:"silence_reason"`
}

func (h *Handler) UpdateAlertSettings(c *gin.Context) {
	var req alertSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.BadRequest(c, "参数格式不正确")
		return
	}

	in := make(map[service.SettingKey]string, 5)
	if req.Enabled != nil {
		in[service.KeyAlertEnabled] = strconv.FormatBool(*req.Enabled)
	}
	if req.WebhookURL != nil {
		raw := strings.TrimSpace(*req.WebhookURL)
		if raw == service.SecretMask {
			raw = h.svc.AlertConfig().WebhookURL
		}
		in[service.KeyAlertWebhook] = raw
	}
	if req.ErrorRatePct != nil {
		in[service.KeyAlertErrorRate] = strconv.Itoa(int(*req.ErrorRatePct))
	}
	if req.DiskPct != nil {
		in[service.KeyAlertDisk] = strconv.Itoa(int(*req.DiskPct))
	}
	if req.BackupStaleHour != nil {
		in[service.KeyAlertBackupHours] = strconv.Itoa(*req.BackupStaleHour)
	}
	if req.SustainedWindows != nil {
		in[service.KeyAlertSustained] = strconv.Itoa(*req.SustainedWindows)
	}
	if req.SilenceUntil != nil {
		raw := strings.TrimSpace(*req.SilenceUntil)
		if raw != "" {
			// 前端 Date.toISOString() 带毫秒：统一成秒级 UTC 再落库。
			if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				raw = t.UTC().Format(time.RFC3339)
			}
		}
		in[service.KeyAlertSilenceUntil] = raw
		// 结束静默时顺手清掉原因，避免下次静默沿用上一次的说明。
		if raw == "" && req.SilenceReason == nil {
			in[service.KeyAlertSilenceReason] = ""
		}
	}
	if req.SilenceReason != nil {
		in[service.KeyAlertSilenceReason] = strings.TrimSpace(*req.SilenceReason)
	}
	if len(in) == 0 {
		httpx.BadRequest(c, "没有需要更新的字段")
		return
	}

	if err := h.svc.UpdateSettings(in); err != nil {
		shared.Fail(c, err)
		return
	}
	cfg := h.svc.AlertConfig()
	silence := "未静默"
	if !cfg.SilenceUntil.IsZero() {
		silence = "静默至 " + cfg.SilenceUntil.Format(time.RFC3339)
		if cfg.SilenceReason != "" {
			silence += "（" + cfg.SilenceReason + "）"
		}
	}
	h.audit(c, "alert.settings.update", "alert", "",
		fmt.Sprintf("更新告警设置（启用=%v，错误率阈值=%.0f%%，磁盘阈值=%.0f%%，备份超时=%d 小时，持续=%d 窗口，%s）",
			cfg.Enabled, cfg.ErrorRatePct, cfg.DiskPct, cfg.BackupStaleHr, cfg.SustainedWindows, silence))
	httpx.OK(c, gin.H{"message": "已保存，配置即时生效"})
}

// TestAlertWebhook 用一条测试消息验证地址可达，不写入告警历史，也不占用冷却窗口。
func (h *Handler) TestAlertWebhook(c *gin.Context) {
	if err := h.svc.TestAlertWebhook(); err != nil {
		if errors.Is(err, service.ErrInvalidParam) {
			shared.Fail(c, err)
			return
		}
		// Webhook 地址本身就是凭据，审计日志里不能留完整 URL。
		reason := outbound.SanitizeError(err).Error()
		h.audit(c, "alert.settings.test_failed", "alert", "", reason)
		httpx.Fail(c, http.StatusBadGateway, "推送失败："+reason)
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

// ResolveAlertEvent 手动关闭一条仍在 firing 的告警。
// 冷却窗口内即使条件仍在也不会再提醒，相当于一次有审计记录的静默。
func (h *Handler) ResolveAlertEvent(c *gin.Context) {
	id, err := parseID(c)
	if err != nil {
		httpx.BadRequest(c, "非法的告警 ID")
		return
	}
	if err := h.svc.ResolveAlertEvent(id); err != nil {
		shared.Fail(c, err)
		return
	}
	h.audit(c, "alert.resolve", "alert", strconv.FormatUint(uint64(id), 10), "手动解决告警")
	httpx.OK(c, gin.H{"message": "已标记为手动解决"})
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
