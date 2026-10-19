package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 通知类邮件（告警、摘要）复用现有的发件箱：重试、租约、失败上限都不用重写。
// 这里只负责「什么时候发、发给谁、正文写什么」。
const (
	maxNotifyRecipients = 10

	reportCheckInterval = 5 * time.Minute
	alertMailWindow     = time.Hour
)

// ParseMailRecipients 解析逗号/分号/空白分隔的收件人列表，返回合法地址与无法识别的原始项。
// 大小写与重复项会被归一，避免同一个人收到多封。
func ParseMailRecipients(raw string) (valid []string, invalid []string) {
	seen := make(map[string]bool)
	for _, part := range splitEmailDomainList(raw) {
		v := strings.ToLower(strings.TrimSpace(part))
		if v == "" || seen[v] {
			continue
		}
		if !IsValidEmail(v) {
			invalid = append(invalid, part)
			continue
		}
		seen[v] = true
		valid = append(valid, v)
	}
	return valid, invalid
}

func levelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func levelLabelCN(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "严重"
	case "warning":
		return "警告"
	case "info":
		return "提示"
	default:
		return level
	}
}

func kindLabelCN(kind string) string {
	switch kind {
	case "error_rate":
		return "接口错误率"
	case "disk":
		return "磁盘水位"
	case "backup_stale":
		return "备份超时"
	case "test":
		return "测试"
	default:
		return kind
	}
}

func formatFloat(v float64) string {
	return fmt.Sprintf("%.1f", v)
}

func formatDurationCN(d time.Duration) string {
	if d < time.Minute {
		return "不到 1 分钟"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 小时 %d 分", hours, minutes)
	default:
		return fmt.Sprintf("%d 分钟", minutes)
	}
}

func formatBytesCN(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

// sendAlertEmail 把一条告警投递到发件箱，返回是否至少入队一封。
// 邮件与 Webhook 是两条独立通道：Webhook 失败不该连累邮件，反之亦然。
func (s *Services) sendAlertEmail(ev model.AlertEvent, resolved bool) bool {
	cfg := s.AlertConfig()
	if !cfg.EmailEnabled || len(cfg.EmailRecipients) == 0 || !s.MailEnabled() {
		return false
	}
	if resolved && !cfg.EmailIncludeRecovery {
		return false
	}
	if !resolved && levelRank(ev.Level) < levelRank(cfg.EmailMinLevel) {
		return false
	}
	if s.alertMailOverLimit(cfg.EmailHourlyLimit) {
		log.Printf("[alert] 邮件通知已达每小时上限（%d 封），本轮跳过（%s）",
			cfg.EmailHourlyLimit, ev.Kind)
		return false
	}

	vars := map[string]string{
		"site_name":   s.Settings.Get(KeySiteName),
		"kind_label":  kindLabelCN(ev.Kind),
		"level_label": levelLabelCN(ev.Level),
		"message":     ev.Message,
		"value":       formatFloat(ev.Value),
		"threshold":   formatFloat(ev.Threshold),
		"fired_at":    ev.CreatedAt.Format("2006-01-02 15:04:05"),
		"resolved_at": "",
		"duration":    "",
	}
	event, kind := MailEventAlertFiring, model.MailKindAlertFiring
	if resolved {
		event, kind = MailEventAlertResolved, model.MailKindAlertResolved
		if ev.ResolvedAt != nil {
			vars["resolved_at"] = ev.ResolvedAt.Format("2006-01-02 15:04:05")
			vars["duration"] = formatDurationCN(ev.ResolvedAt.Sub(ev.CreatedAt))
		}
	}

	subject, body := s.renderMail(event, vars)
	if subject == "" || body == "" {
		log.Printf("[alert] 告警邮件模板缺失（%s），已跳过", event)
		return false
	}

	queued := false
	for _, to := range cfg.EmailRecipients {
		if err := s.enqueueMail(to, subject, body, kind, nil, mailQuota{}); err != nil {
			log.Printf("[alert] 告警邮件入队失败（收件人 %s）: %v", maskEmail(to), err)
			continue
		}
		queued = true
	}
	return queued
}

// alertMailOverLimit 按「封数」限制告警邮件，防止一个抖动指标把邮箱刷爆。
// 统计失败时返回 false：宁可多发一封，也不要因为一次查询失败把告警吞掉。
func (s *Services) alertMailOverLimit(limit int) bool {
	if limit <= 0 {
		return false
	}
	var n int64
	err := s.DB.Model(&model.MailOutbox{}).
		Where("kind IN ? AND created_at >= ?",
			[]string{model.MailKindAlertFiring, model.MailKindAlertResolved},
			time.Now().Add(-alertMailWindow)).
		Count(&n).Error
	if err != nil {
		log.Printf("[alert] 统计告警邮件数量失败，跳过限流: %v", err)
		return false
	}
	return n >= int64(limit)
}

// ReportConfig 是定时报告的运行期配置。收件人复用告警邮件的那一份列表：
// 单管理员场景下维护两个列表只会带来「改了告警没改报告」的困惑。
type ReportConfig struct {
	Enabled       bool
	DailyEnabled  bool
	DailyHour     int
	WeeklyEnabled bool
	WeeklyWeekday int // 1=周一 … 7=周日
	WeeklyHour    int
	Recipients    []string
}

func (s *Services) ReportConfig() ReportConfig {
	recipients, _ := ParseMailRecipients(s.Settings.Get(KeyAlertEmailTo))
	return ReportConfig{
		Enabled:       s.Settings.Bool(KeyReportEnabled),
		DailyEnabled:  s.Settings.Bool(KeyReportDailyEnabled),
		DailyHour:     clampInt(s.Settings.Int(KeyReportDailyHour), 0, 23),
		WeeklyEnabled: s.Settings.Bool(KeyReportWeeklyEnabled),
		WeeklyWeekday: clampInt(s.Settings.Int(KeyReportWeeklyWeekday), 1, 7),
		WeeklyHour:    clampInt(s.Settings.Int(KeyReportWeeklyHour), 0, 23),
		Recipients:    recipients,
	}
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// StartReportWorker 每 5 分钟检查一次是否有到点的日报/周报。
// 是否「已经发过」记在内部设置里，重启后不会重复发。
func (s *Services) StartReportWorker(ctx context.Context) <-chan struct{} {
	if cfg := s.ReportConfig(); cfg.Enabled {
		log.Printf("[report] 定时报告已启用：日报 %v（%d 点），周报 %v（周%d %d 点）",
			cfg.DailyEnabled, cfg.DailyHour, cfg.WeeklyEnabled, cfg.WeeklyWeekday, cfg.WeeklyHour)
	} else {
		log.Printf("[report] 定时报告未启用，可在管理端「告警与监控」中开启")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(reportCheckInterval)
		defer ticker.Stop()
		s.runDueReports(time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runDueReports(time.Now())
			}
		}
	}()
	return done
}

func (s *Services) runDueReports(now time.Time) {
	cfg := s.ReportConfig()
	if !cfg.Enabled || len(cfg.Recipients) == 0 || !s.MailEnabled() {
		return
	}
	if cfg.DailyEnabled {
		if due, start, end := s.dailyReportWindow(cfg, now); due {
			s.sendSummaryReport("daily", start, end, now)
		}
	}
	if cfg.WeeklyEnabled {
		if due, start, end := s.weeklyReportWindow(cfg, now); due {
			s.sendSummaryReport("weekly", start, end, now)
		}
	}
}

// dailyReportWindow 返回「今天这一期是否该发」以及统计区间。
// 区间固定为截止时间往前 24 小时，与实际运行时刻无关，补发时口径一致。
func (s *Services) dailyReportWindow(cfg ReportConfig, now time.Time) (bool, time.Time, time.Time) {
	scheduled := time.Date(now.Year(), now.Month(), now.Day(), cfg.DailyHour, 0, 0, 0, now.Location())
	if now.Before(scheduled) {
		return false, time.Time{}, time.Time{}
	}
	if last := parseSettingTime(s.Settings.Get(KeyReportDailyLastAt)); !last.IsZero() && !last.Before(scheduled) {
		return false, time.Time{}, time.Time{}
	}
	return true, scheduled.AddDate(0, 0, -1), scheduled
}

// weeklyReportWindow 取「最近一次到点的周报时刻」，因此停机错过一天也能补发。
func (s *Services) weeklyReportWindow(cfg ReportConfig, now time.Time) (bool, time.Time, time.Time) {
	occurrence := lastWeeklyOccurrence(now, cfg.WeeklyWeekday, cfg.WeeklyHour)
	if last := parseSettingTime(s.Settings.Get(KeyReportWeeklyLastAt)); !last.IsZero() && !last.Before(occurrence) {
		return false, time.Time{}, time.Time{}
	}
	return true, occurrence.AddDate(0, 0, -7), occurrence
}

// lastWeeklyOccurrence 返回不晚于 now 的最近一个「周 X 的 hour:00」。
func lastWeeklyOccurrence(now time.Time, weekday, hour int) time.Time {
	mondayBased := (int(now.Weekday()) + 6) % 7 // 周一=0 … 周日=6
	target := clampInt(weekday, 1, 7) - 1
	delta := mondayBased - target
	if delta < 0 {
		delta += 7
	}
	occ := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location()).
		AddDate(0, 0, -delta)
	if occ.After(now) {
		occ = occ.AddDate(0, 0, -7)
	}
	return occ
}

func parseSettingTime(raw string) time.Time {
	v := strings.TrimSpace(raw)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// SendTestReport 立即入队一份最近 24 小时的摘要，用于验证 SMTP 与模板。
// 不写发送标记，因此不会影响正常日报的节奏。
func (s *Services) SendTestReport(now time.Time) error {
	if !s.MailEnabled() {
		return fmt.Errorf("%w: 邮件功能未启用，请先在「系统设置 → 邮件」里配置", ErrInvalidParam)
	}
	cfg := s.ReportConfig()
	if len(cfg.Recipients) == 0 {
		return fmt.Errorf("%w: 请先填写通知邮箱", ErrInvalidParam)
	}
	if s.enqueueSummaryReport(cfg, "daily", now.Add(-24*time.Hour), now, now) == 0 {
		return fmt.Errorf("摘要邮件入队失败，请检查服务日志")
	}
	return nil
}

func (s *Services) sendSummaryReport(kind string, start, end, now time.Time) {
	cfg := s.ReportConfig()
	if s.enqueueSummaryReport(cfg, kind, start, end, now) == 0 {
		return
	}

	marker := KeyReportDailyLastAt
	if kind == "weekly" {
		marker = KeyReportWeeklyLastAt
	}
	if err := s.Settings.SetInternal(map[SettingKey]string{
		marker: now.UTC().Format(time.RFC3339),
	}); err != nil {
		log.Printf("[report] 记录 %s 发送时间失败（下轮可能重复发送）: %v", kind, err)
	}
	log.Printf("[report] 已入队%s", map[string]string{"daily": "日报", "weekly": "周报"}[kind])
}

// enqueueSummaryReport 生成并投递摘要邮件，返回成功入队的封数。
func (s *Services) enqueueSummaryReport(cfg ReportConfig, kind string, start, end, now time.Time) int {
	data := s.buildReportData(start, end, now)

	reportName := "日报"
	if kind == "weekly" {
		reportName = "周报"
	}
	vars := map[string]string{
		"site_name":       s.Settings.Get(KeySiteName),
		"report_name":     reportName,
		"period":          fmt.Sprintf("%s ~ %s", start.Format("2006-01-02 15:04"), end.Format("2006-01-02 15:04")),
		"generated_at":    now.Format("2006-01-02 15:04:05"),
		"users_total":     fmt.Sprintf("%d", data.UsersTotal),
		"users_new":       fmt.Sprintf("%d", data.UsersNew),
		"tunnels_total":   fmt.Sprintf("%d", data.TunnelsTotal),
		"tunnels_online":  fmt.Sprintf("%d", data.TunnelsOnline),
		"traffic":         formatBytesCN(data.TrafficIn + data.TrafficOut),
		"error_rate":      fmt.Sprintf("%.2f", data.ErrorRateAvg),
		"disk":            fmt.Sprintf("%.1f", data.DiskPct),
		"last_backup":     data.lastBackupText(),
		"alerts_firing":   fmt.Sprintf("%d", data.AlertsFiring),
		"alerts_resolved": fmt.Sprintf("%d", data.AlertsResolved),
		"alert_lines":     data.alertLines(),
	}

	subject, body := s.renderMail(MailEventReportSummary, vars)
	if subject == "" || body == "" {
		log.Printf("[report] 摘要邮件模板缺失，已跳过（%s）", kind)
		return 0
	}

	queued := 0
	for _, to := range cfg.Recipients {
		if err := s.enqueueMail(to, subject, body, model.MailKindReportSummary, nil, mailQuota{}); err != nil {
			log.Printf("[report] 摘要邮件入队失败（收件人 %s）: %v", maskEmail(to), err)
			continue
		}
		queued++
	}
	if queued > 0 {
		log.Printf("[report] 摘要邮件已入队（%s，%d 封）", reportName, queued)
	}
	return queued
}

type reportData struct {
	UsersTotal     int64
	UsersNew       int64
	TunnelsTotal   int64
	TunnelsOnline  int64
	TrafficIn      int64
	TrafficOut     int64
	AlertsFiring   int64
	AlertsResolved int64
	ErrorRateAvg   float64
	DiskPct        float64
	BackupHours    float64
	HasBackup      bool
	Recent         []model.AlertEvent
}

func (d reportData) lastBackupText() string {
	if !d.HasBackup {
		return "无可用备份"
	}
	if d.BackupHours < 1 {
		return "1 小时内"
	}
	return fmt.Sprintf("%.0f 小时前", d.BackupHours)
}

func (d reportData) alertLines() string {
	if len(d.Recent) == 0 {
		return "<li>本期没有新告警</li>"
	}
	var b strings.Builder
	for _, ev := range d.Recent {
		msg := ev.Message
		if len([]rune(msg)) > 120 {
			msg = string([]rune(msg)[:120]) + "…"
		}
		fmt.Fprintf(&b, "<li>%s · %s：%s</li>",
			levelLabelCN(ev.Level), kindLabelCN(ev.Kind), msg)
	}
	return b.String()
}

// buildReportData 汇总统计区间内的数据。任何一项查询失败都只记日志并留空，
// 不让一份摘要邮件因为某个次要统计失败而整体发不出去。
func (s *Services) buildReportData(start, end, now time.Time) reportData {
	var d reportData
	db := s.DB

	if err := db.Model(&model.User{}).Count(&d.UsersTotal).Error; err != nil {
		log.Printf("[report] 统计用户总数失败: %v", err)
	}
	if err := db.Model(&model.User{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&d.UsersNew).Error; err != nil {
		log.Printf("[report] 统计新增用户失败: %v", err)
	}
	if err := db.Model(&model.Tunnel{}).Count(&d.TunnelsTotal).Error; err != nil {
		log.Printf("[report] 统计隧道总数失败: %v", err)
	}
	var tunnels []model.Tunnel
	if err := db.Select("id", "status", "last_online_at").
		Where("status = ?", model.TunnelStatusActive).Find(&tunnels).Error; err != nil {
		log.Printf("[report] 读取隧道列表失败: %v", err)
	} else {
		for i := range tunnels {
			if s.IsTunnelOnline(&tunnels[i]) {
				d.TunnelsOnline++
			}
		}
	}

	var traffic struct {
		InBytes  int64
		OutBytes int64
	}
	if err := db.Model(&model.TrafficDaily{}).
		Select("COALESCE(SUM(in_bytes),0) AS in_bytes, COALESCE(SUM(out_bytes),0) AS out_bytes").
		Where("date >= ? AND date <= ?", start.Format("2006-01-02"), end.Format("2006-01-02")).
		Scan(&traffic).Error; err != nil {
		log.Printf("[report] 统计流量失败: %v", err)
	}
	d.TrafficIn, d.TrafficOut = traffic.InBytes, traffic.OutBytes

	if err := db.Model(&model.AlertEvent{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&d.AlertsFiring).Error; err != nil {
		log.Printf("[report] 统计新增告警失败: %v", err)
	}
	if err := db.Model(&model.AlertEvent{}).
		Where("resolved_at >= ? AND resolved_at < ?", start, end).
		Count(&d.AlertsResolved).Error; err != nil {
		log.Printf("[report] 统计恢复告警失败: %v", err)
	}

	var avg struct {
		Rate float64
		Disk float64
	}
	if err := db.Model(&model.MetricSample{}).
		Select("COALESCE(AVG(error_rate),0) AS rate, COALESCE(MAX(disk_used_pct),0) AS disk").
		Where("sampled_at >= ? AND sampled_at < ?", start, end).
		Scan(&avg).Error; err != nil {
		log.Printf("[report] 统计指标失败: %v", err)
	}
	d.ErrorRateAvg, d.DiskPct = avg.Rate, avg.Disk

	if hours, ok := s.backupStaleHours(now); ok {
		d.HasBackup, d.BackupHours = true, hours
	}

	if err := db.Model(&model.AlertEvent{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Order("id DESC").Limit(5).Find(&d.Recent).Error; err != nil {
		log.Printf("[report] 读取告警摘要失败: %v", err)
	}
	return d
}
