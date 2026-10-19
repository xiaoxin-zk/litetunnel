package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这些数值会展示在管理端，导出出去避免页面另写一份。
const (
	AlertIntervalMinutes = 5
	AlertCooldownMinutes = 30
	AlertMinRequests     = 50
	AlertSampleKeepDays  = 14
	AlertEventKeepDays   = 90
)

const (
	alertInterval    = AlertIntervalMinutes * time.Minute
	alertCooldown    = AlertCooldownMinutes * time.Minute
	alertMinRequests = AlertMinRequests
	metricSampleKeep = AlertSampleKeepDays * 24 * time.Hour
	alertEventKeep   = AlertEventKeepDays * 24 * time.Hour
)

type AlertConfig struct {
	Enabled       bool    `json:"enabled"`
	WebhookURL    string  `json:"webhook_url"`
	ErrorRatePct  float64 `json:"error_rate_pct"`
	DiskPct       float64 `json:"disk_pct"`
	BackupStaleHr int     `json:"backup_stale_hours"`
}

func (s *Services) AlertConfig() AlertConfig {
	return AlertConfig{
		Enabled:       s.Settings.Bool(KeyAlertEnabled),
		WebhookURL:    strings.TrimSpace(s.Settings.Get(KeyAlertWebhook)),
		ErrorRatePct:  float64(s.Settings.Int(KeyAlertErrorRate)),
		DiskPct:       float64(s.Settings.Int(KeyAlertDisk)),
		BackupStaleHr: s.Settings.Int(KeyAlertBackupHours),
	}
}

// StartAlertWorker 每 5 分钟采一次样并评估阈值。采样落库，供面板画趋势。
func (s *Services) StartAlertWorker(ctx context.Context) <-chan struct{} {
	if cfg := s.AlertConfig(); cfg.Enabled && cfg.WebhookURL != "" {
		log.Printf("[alert] 告警已启用：每 %d 分钟采样；错误率 ≥ %.0f%%、磁盘 ≥ %.0f%%、备份超时 ≥ %d 小时时推送",
			AlertIntervalMinutes, cfg.ErrorRatePct, cfg.DiskPct, cfg.BackupStaleHr)
	} else {
		log.Printf("[alert] 告警未启用，仅采样指标（管理端「告警与监控」可开启）")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(alertInterval)
		defer ticker.Stop()
		s.runAlertCycle(time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runAlertCycle(time.Now())
			}
		}
	}()
	return done
}

func (s *Services) runAlertCycle(now time.Time) {
	stats := middleware.HTTPStatsSnapshotAndReset()

	sample := model.MetricSample{
		At: now, Requests: stats.Total, Errors: stats.Errors,
	}
	if stats.Total > 0 {
		sample.ErrorRate = float64(stats.Errors) / float64(stats.Total) * 100
	}
	if latest := s.Monitor.Latest(); latest.DiskTotal > 0 {
		sample.DiskUsedPct = float64(latest.DiskUsed) / float64(latest.DiskTotal) * 100
	}
	if err := s.DB.Create(&sample).Error; err != nil {
		log.Printf("[alert] 写入指标样本失败: %v", err)
	}
	s.DB.Where("sampled_at < ?", now.Add(-metricSampleKeep)).Delete(&model.MetricSample{})
	// 冷却只看同类最新一条，因此清理三个月前的历史不会影响去抖。
	s.DB.Where("created_at < ?", now.Add(-alertEventKeep)).Delete(&model.AlertEvent{})

	cfg := s.AlertConfig()
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return
	}

	if cfg.ErrorRatePct > 0 && stats.Total >= alertMinRequests && sample.ErrorRate >= cfg.ErrorRatePct {
		s.raiseAlert("error_rate", "warning",
			fmt.Sprintf("接口错误率 %.1f%%（阈值 %.0f%%，样本 %d 次请求）",
				sample.ErrorRate, cfg.ErrorRatePct, stats.Total),
			sample.ErrorRate, cfg.ErrorRatePct)
	}
	if cfg.DiskPct > 0 && sample.DiskUsedPct >= cfg.DiskPct {
		s.raiseAlert("disk", "critical",
			fmt.Sprintf("磁盘使用率 %.1f%%（阈值 %.0f%%）", sample.DiskUsedPct, cfg.DiskPct),
			sample.DiskUsedPct, cfg.DiskPct)
	}
	if cfg.BackupStaleHr > 0 {
		if hours, ok := s.backupStaleHours(now); ok && hours >= float64(cfg.BackupStaleHr) {
			s.raiseAlert("backup_stale", "warning",
				fmt.Sprintf("已有 %.0f 小时没有成功备份（阈值 %d 小时）", hours, cfg.BackupStaleHr),
				hours, float64(cfg.BackupStaleHr))
		}
	}
}

func (s *Services) backupStaleHours(now time.Time) (float64, bool) {
	if !s.BackupSupported() {
		return 0, false
	}
	list, err := s.ListBackups()
	if err != nil {
		return 0, false
	}
	for _, f := range list {
		if f.PreRestore {
			continue
		}
		return now.Sub(f.CreatedAt).Hours(), true
	}
	return 1 << 20, true // 一个都没有：视为早已过期的极值
}

// raiseAlert 受冷却时间约束，避免同一个问题每五分钟刷一次 Webhook。
func (s *Services) raiseAlert(kind, level, message string, value, threshold float64) {
	var last model.AlertEvent
	err := s.DB.Where("kind = ?", kind).Order("id DESC").First(&last).Error
	if err == nil && time.Since(last.CreatedAt) < alertCooldown {
		return
	}
	ev := model.AlertEvent{Kind: kind, Level: level, Message: message, Value: value, Threshold: threshold}
	if err := s.DB.Create(&ev).Error; err != nil {
		log.Printf("[alert] 记录告警失败: %v", err)
		return
	}
	if err := s.postWebhook(ev); err != nil {
		log.Printf("[alert] Webhook 推送失败（%s）: %v", kind, err)
		return
	}
	s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).Update("delivered", true)
}

func (s *Services) postWebhook(ev model.AlertEvent) error {
	cfg := s.AlertConfig()
	if cfg.WebhookURL == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"kind":      ev.Kind,
		"level":     ev.Level,
		"message":   ev.Message,
		"value":     ev.Value,
		"threshold": ev.Threshold,
		"site":      s.Settings.Get(KeySiteName),
		"at":        ev.CreatedAt.Format(time.RFC3339),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LiteTunnel-Alert")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// TestAlertWebhook 用一条测试消息验证地址可达，不写告警历史。
func (s *Services) TestAlertWebhook() error {
	if strings.TrimSpace(s.Settings.Get(KeyAlertWebhook)) == "" {
		return fmt.Errorf("%w: 请先填写 Webhook 地址", ErrInvalidParam)
	}
	return s.postWebhook(model.AlertEvent{
		Kind: "test", Level: "info", Message: "这是一条来自 LiteTunnel 的测试告警",
		CreatedAt: time.Now(),
	})
}

func (s *Services) ListAlertEvents(limit int) ([]model.AlertEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []model.AlertEvent
	err := s.DB.Order("id DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (s *Services) ListMetricSamples(limit int) ([]model.MetricSample, error) {
	if limit <= 0 || limit > 2016 {
		limit = 288
	}
	var out []model.MetricSample
	err := s.DB.Order("sampled_at DESC").Limit(limit).Find(&out).Error
	return out, err
}
