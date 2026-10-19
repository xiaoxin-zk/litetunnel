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
	"github.com/xiaoxin-zk/litetunnel/server/internal/outbound"
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

	// SustainedWindows 是触发前需要连续超标的采样窗口数（1 表示立即触发）。
	SustainedWindows int       `json:"sustained_windows"`
	SilenceUntil     time.Time `json:"silence_until"`
	SilenceReason    string    `json:"silence_reason"`
}

// Silenced 报告 now 是否处于静默窗口内。静默只影响推送，不影响状态维护。
func (c AlertConfig) Silenced(now time.Time) bool {
	return !c.SilenceUntil.IsZero() && now.Before(c.SilenceUntil)
}

func (s *Services) AlertConfig() AlertConfig {
	sustained := s.Settings.Int(KeyAlertSustained)
	if sustained < 1 {
		sustained = 1
	}
	return AlertConfig{
		Enabled:          s.Settings.Bool(KeyAlertEnabled),
		WebhookURL:       strings.TrimSpace(s.Settings.Get(KeyAlertWebhook)),
		ErrorRatePct:     float64(s.Settings.Int(KeyAlertErrorRate)),
		DiskPct:          float64(s.Settings.Int(KeyAlertDisk)),
		BackupStaleHr:    s.Settings.Int(KeyAlertBackupHours),
		SustainedWindows: sustained,
		SilenceUntil:     parseSilenceUntil(s.Settings.Get(KeyAlertSilenceUntil)),
		SilenceReason:    strings.TrimSpace(s.Settings.Get(KeyAlertSilenceReason)),
	}
}

// parseSilenceUntil 解析静默截止时间。非法值当作未静默：
// 配置损坏时宁可恢复告警，也不要静默地把告警全部吞掉。
func parseSilenceUntil(raw string) time.Time {
	v := strings.TrimSpace(raw)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return t
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
	diskKnown := false
	if latest := s.Monitor.Latest(); latest.DiskTotal > 0 {
		sample.DiskUsedPct = float64(latest.DiskUsed) / float64(latest.DiskTotal) * 100
		diskKnown = true
	}
	if err := s.DB.Create(&sample).Error; err != nil {
		log.Printf("[alert] 写入指标样本失败: %v", err)
	}
	s.DB.Where("sampled_at < ?", now.Add(-metricSampleKeep)).Delete(&model.MetricSample{})
	// 冷却只看同类最新一条，因此清理历史不会影响去抖；
	// 仍在 firing 的事件不删，否则一条长期未恢复的告警会悄悄从面板上消失。
	s.DB.Where("created_at < ? AND status <> ?", now.Add(-alertEventKeep), model.AlertStatusFiring).
		Delete(&model.AlertEvent{})

	cfg := s.AlertConfig()
	// 静默与关闭告警的区别：静默只是不打扰（不新建事件、不推送），状态仍然维护；
	// 关闭告警则连评估都不做推送，但已有事件照样会按条件恢复。
	notify := cfg.Enabled && cfg.WebhookURL != "" && !cfg.Silenced(now)

	checks := s.evaluateAlerts(cfg, sample, stats, diskKnown, now)
	evaluated := make(map[string]struct{}, len(checks))
	for _, c := range checks {
		evaluated[c.kind] = struct{}{}
		if c.skip {
			// 本窗口数据不足（请求太少、磁盘还没采到、备份列表读失败）：
			// 既不算命中也不算恢复，否则会把正在响的告警误标成「已恢复」。
			continue
		}
		if c.breaching {
			// 命中但还没达到持续窗口数时不触发，也不恢复（恢复只看当前窗口）。
			if notify && c.fire {
				s.raiseAlert(c.kind, c.level, c.message, c.value, c.threshold)
			}
			continue
		}
		// 当前窗口恢复正常就收尾：恢复不要求持续，避免「降下来又弹回去」时告警长期不消。
		s.resolveAlert(c.kind, c.recovered)
	}

	// 某项检查被关掉（阈值 0）或当前环境不支持时，把遗留的进行中事件收尾，
	// 否则面板上会永远挂着一条再也不会更新的 firing。
	for _, kind := range []string{"error_rate", "disk", "backup_stale"} {
		if _, ok := evaluated[kind]; ok {
			continue
		}
		s.resolveAlert(kind, "该检查已关闭或当前环境不支持，历史告警自动结束")
	}
}

// alertCheck 是一轮评估的结果。
// breaching 表示「当前窗口超标」，fire 表示「满足持续窗口数、可以触发」；
// 恢复只看 breaching，不看 fire。
type alertCheck struct {
	kind      string
	level     string
	breaching bool
	fire      bool
	skip      bool // 数据不足，本窗口不做判定
	message   string
	recovered string
	value     float64
	threshold float64
}

// evaluateAlerts 只做判断，不写事件表，阈值口径集中在这里。
func (s *Services) evaluateAlerts(
	cfg AlertConfig, sample model.MetricSample, stats middleware.HTTPStatsSnapshot,
	diskKnown bool, now time.Time,
) []alertCheck {
	checks := make([]alertCheck, 0, 3)

	if cfg.ErrorRatePct > 0 {
		// 请求数不足的窗口不参与判断：几个请求里错一个就是 50%，会变成噪声。
		breaching := stats.Total >= alertMinRequests && sample.ErrorRate >= cfg.ErrorRatePct
		checks = append(checks, alertCheck{
			kind:      "error_rate",
			level:     "warning",
			breaching: breaching,
			skip:      stats.Total < alertMinRequests,
			fire: breaching && s.sustained(cfg.SustainedWindows, now, func(r model.MetricSample) bool {
				return r.Requests >= alertMinRequests && r.ErrorRate >= cfg.ErrorRatePct
			}),
			message: fmt.Sprintf("接口错误率 %.1f%%（阈值 %.0f%%，样本 %d 次请求）",
				sample.ErrorRate, cfg.ErrorRatePct, stats.Total),
			recovered: fmt.Sprintf("接口错误率已回落至 %.1f%%（阈值 %.0f%%）", sample.ErrorRate, cfg.ErrorRatePct),
			value:     sample.ErrorRate,
			threshold: cfg.ErrorRatePct,
		})
	}
	if cfg.DiskPct > 0 {
		breaching := diskKnown && sample.DiskUsedPct >= cfg.DiskPct
		checks = append(checks, alertCheck{
			kind:      "disk",
			level:     "critical",
			breaching: breaching,
			skip:      !diskKnown,
			fire: breaching && s.sustained(cfg.SustainedWindows, now, func(r model.MetricSample) bool {
				return r.DiskUsedPct >= cfg.DiskPct
			}),
			message:   fmt.Sprintf("磁盘使用率 %.1f%%（阈值 %.0f%%）", sample.DiskUsedPct, cfg.DiskPct),
			recovered: fmt.Sprintf("磁盘使用率已回落至 %.1f%%（阈值 %.0f%%）", sample.DiskUsedPct, cfg.DiskPct),
			value:     sample.DiskUsedPct,
			threshold: cfg.DiskPct,
		})
	}
	if cfg.BackupStaleHr > 0 && s.BackupSupported() {
		if hours, ok := s.backupStaleHours(now); ok {
			breaching := hours >= float64(cfg.BackupStaleHr)
			checks = append(checks, alertCheck{
				kind: "backup_stale",
				// 备份超时本身以小时计，再要求「连续 N 个窗口」只会白白延后提醒。
				level:     "warning",
				breaching: breaching,
				fire:      breaching,
				message:   fmt.Sprintf("已有 %.0f 小时没有成功备份（阈值 %d 小时）", hours, cfg.BackupStaleHr),
				recovered: fmt.Sprintf("备份已恢复（最近一次成功备份在 %.0f 小时前）", hours),
				value:     hours,
				threshold: float64(cfg.BackupStaleHr),
			})
		} else {
			// 目录读不出来：不能据此判定「已恢复」。
			checks = append(checks, alertCheck{kind: "backup_stale", skip: true})
		}
	}
	return checks
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

// sustained 判断最近 n 个采样窗口（含当前窗口）是否都满足条件。
// 用落库样本回溯而不是进程内计数：进程重启后判断仍然成立，
// 多实例看到的也是同一份历史。
func (s *Services) sustained(n int, at time.Time, ok func(model.MetricSample) bool) bool {
	if n <= 1 {
		return true
	}
	var rows []model.MetricSample
	if err := s.DB.Where("sampled_at <= ?", at).Order("sampled_at DESC").Limit(n).Find(&rows).Error; err != nil {
		log.Printf("[alert] 读取指标样本失败，本轮按「未持续」处理: %v", err)
		return false
	}
	if len(rows) < n {
		return false
	}
	// 进程停过一段时间时，库里的「最近 N 条」可能横跨几个小时。
	// 这种情况不能算「连续」：否则重启后会拿停机前的样本凑数，误报一次。
	if oldest := rows[len(rows)-1]; at.Sub(oldest.At) > time.Duration(n)*alertInterval*2 {
		return false
	}
	for _, r := range rows {
		if !ok(r) {
			return false
		}
	}
	return true
}

// raiseAlert 维护「同一 kind 同时最多一条 firing」的约束：
//   - 已在 firing：没送达就重试；送达过则每 30 分钟提醒一次（同一条记录）；
//   - 自动恢复后冷却窗口内再次命中：视为同一次抖动，静默重开同一条；
//   - 手动解决后冷却窗口内再次命中：尊重管理员的处置，不再打扰；
//   - 超过冷却：开一条新事件并推送。
func (s *Services) raiseAlert(kind, level, message string, value, threshold float64) {
	var last model.AlertEvent
	if err := s.DB.Where("kind = ?", kind).Order("id DESC").First(&last).Error; err == nil {
		switch {
		case last.Status == model.AlertStatusFiring:
			if !last.Delivered {
				s.deliverAlert(last)
				return
			}
			// 同一事件每 30 分钟提醒一次：长期故障不会只在开头响一声，
			// 而「静默重开」的复发也靠这里重新通知，不必再开新行。
			if last.LastNotifiedAt == nil || time.Since(*last.LastNotifiedAt) >= alertCooldown {
				last.Message = message
				last.Value = value
				last.Threshold = threshold
				s.refreshAlert(&last)
				s.deliverAlert(last)
			}
			return
		case last.ResolvedAt != nil && time.Since(*last.ResolvedAt) < alertCooldown:
			if last.Status == model.AlertStatusResolved {
				s.reopenAlert(last)
			}
			return
		case last.ResolvedAt == nil && time.Since(last.CreatedAt) < alertCooldown:
			// 老数据没有 resolved_at：退化成按创建时间冷却。
			return
		}
	}

	ev := model.AlertEvent{
		Kind: kind, Level: level, Message: message, Value: value, Threshold: threshold,
		Status: model.AlertStatusFiring,
	}
	if err := s.DB.Create(&ev).Error; err != nil {
		// 唯一索引兜底：并发下另一实例已经开了同一条 firing，复用它的记录。
		var open model.AlertEvent
		if e := s.DB.Where("kind = ? AND status = ?", kind, model.AlertStatusFiring).
			Order("id DESC").First(&open).Error; e == nil {
			if !open.Delivered {
				s.deliverAlert(open)
			}
			return
		}
		log.Printf("[alert] 记录告警失败: %v", err)
		return
	}
	s.deliverAlert(ev)
}

// reopenAlert 把刚恢复的事件重新打开。条件在冷却窗口内复发时当作同一次抖动，
// 不再补发「又炸了」：否则一个每分钟抖一次的指标会变成持续刷屏。
func (s *Services) reopenAlert(ev model.AlertEvent) {
	err := s.DB.Model(&model.AlertEvent{}).
		Where("id = ? AND status = ?", ev.ID, model.AlertStatusResolved).
		Updates(map[string]any{
			"status":      model.AlertStatusFiring,
			"resolved_at": nil,
		}).Error
	if err != nil {
		log.Printf("[alert] 重开告警失败: %v", err)
	}
}

// resolveAlert 把该类型仍在 firing 的事件标记为已恢复，并推送恢复通知。
// 每轮采样对所有未命中的规则都会调用一次，因此必须幂等。
func (s *Services) resolveAlert(kind, message string) {
	var last model.AlertEvent
	if err := s.DB.Where("kind = ?", kind).Order("id DESC").First(&last).Error; err != nil {
		return
	}
	if last.Status != model.AlertStatusFiring {
		// 已恢复但恢复通知没送出去：冷却窗口内顺带补一次（与触发通知的重试对称）。
		if last.Status == model.AlertStatusResolved && !last.ResolvedNotified &&
			last.ResolvedAt != nil && time.Since(*last.ResolvedAt) < alertCooldown {
			s.deliverResolved(last, message)
		}
		return
	}

	now := time.Now()
	res := s.DB.Model(&model.AlertEvent{}).
		Where("id = ? AND status = ?", last.ID, model.AlertStatusFiring).
		Updates(map[string]any{
			"status":      model.AlertStatusResolved,
			"resolved_at": now,
		})
	if res.Error != nil {
		log.Printf("[alert] 标记告警恢复失败: %v", res.Error)
		return
	}
	if res.RowsAffected == 0 {
		return // 并发下已被别的路径处理（例如管理员刚手动解决）
	}
	last.Status = model.AlertStatusResolved
	last.ResolvedAt = &now
	s.deliverResolved(last, message)
}

// ResolveAlertEvent 手动关闭一条仍在 firing 的告警。
// 冷却窗口内即使条件仍在也不会再提醒，相当于一次有记录的「静默」。
func (s *Services) ResolveAlertEvent(id uint) error {
	if id == 0 {
		return fmt.Errorf("%w: 非法的告警 ID", ErrInvalidParam)
	}
	res := s.DB.Model(&model.AlertEvent{}).
		Where("id = ? AND status = ?", id, model.AlertStatusFiring).
		Updates(map[string]any{
			"status":      model.AlertStatusManualResolved,
			"resolved_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: 该告警不存在或已恢复", ErrNotFound)
	}
	return nil
}

// refreshAlert 用最新的观测值刷新事件内容：提醒里要带当前读数，
// 而不是这条事件第一次触发时的读数。
func (s *Services) refreshAlert(ev *model.AlertEvent) {
	if err := s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).
		Updates(map[string]any{
			"message":   ev.Message,
			"value":     ev.Value,
			"threshold": ev.Threshold,
		}).Error; err != nil {
		log.Printf("[alert] 刷新告警内容失败: %v", err)
	}
}

// deliverAlert 推送并回写送达状态。失败只记日志：告警记录本身已经落库，
// 下一轮采样会重试同一条。
func (s *Services) deliverAlert(ev model.AlertEvent) {
	if err := s.postWebhook(ev); err != nil {
		// 地址里通常带 token，日志只记出站策略能安全展示的部分。
		log.Printf("[alert] Webhook 推送失败（%s）: %v", ev.Kind, outbound.SanitizeError(err))
		return
	}
	s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).
		Updates(map[string]any{"delivered": true, "last_notified_at": time.Now()})
}

// deliverResolved 推送恢复通知。触发通知都没送达时不再单发「已恢复」：
// 接收端没看到「炸了」，再来一条「好了」只会让人困惑。
func (s *Services) deliverResolved(ev model.AlertEvent, message string) {
	cfg := s.AlertConfig()
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return
	}
	if cfg.Silenced(time.Now()) {
		// 静默期间不打扰：状态照常恢复，只是不发消息；标记已处理，
		// 避免静默结束后再补一条过期的「已恢复」。
		s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).Update("resolved_notified", true)
		return
	}
	if !ev.Delivered {
		s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).Update("resolved_notified", true)
		return
	}

	out := ev
	out.Status = model.AlertStatusResolved
	out.Level = "info"
	out.Message = message
	if err := s.postWebhook(out); err != nil {
		log.Printf("[alert] 恢复通知推送失败（%s）: %v", ev.Kind, outbound.SanitizeError(err))
		return
	}
	s.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).Update("resolved_notified", true)
}

// postWebhook 推送一条告警。at 是推送时间，fired_at 是事件发生时间，
// 恢复通知额外带 resolved_at，接收端可以据此把同一次故障的几条消息串起来。
func (s *Services) postWebhook(ev model.AlertEvent) error {
	cfg := s.AlertConfig()
	if cfg.WebhookURL == "" {
		return nil
	}
	// 保存时校验过，这里再校验一次：设置可能来自旧版本，或被直接写进了数据库。
	target, err := outbound.ValidateHTTPURL(cfg.WebhookURL)
	if err != nil {
		return fmt.Errorf("%w: Webhook 地址不可用（%v）", ErrInvalidParam, err)
	}
	payload := map[string]any{
		"event_id":  ev.ID,
		"kind":      ev.Kind,
		"status":    ev.Status,
		"level":     ev.Level,
		"message":   ev.Message,
		"value":     ev.Value,
		"threshold": ev.Threshold,
		"site":      s.Settings.Get(KeySiteName),
		"at":        time.Now().Format(time.RFC3339),
		"fired_at":  ev.CreatedAt.Format(time.RFC3339),
	}
	if ev.ResolvedAt != nil {
		payload["resolved_at"] = ev.ResolvedAt.Format(time.RFC3339)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), outbound.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LiteTunnel-Alert")
	resp, err := outbound.Client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("接收端返回 HTTP %d", resp.StatusCode)
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
		Status: "test", CreatedAt: time.Now(),
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
