package service

import (
	"context"
	"fmt"
	"log"
	"strconv"
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
	remaining := s.alertMailRemaining(cfg.EmailHourlyLimit)
	if remaining <= 0 {
		log.Printf("[alert] 邮件通知已达每小时上限（%d 封），本轮跳过（%s）",
			cfg.EmailHourlyLimit, ev.Kind)
		return false
	}
	// 剩余额度不足时只发给前几个收件人：一次告警不该把额度顶穿。
	recipients := cfg.EmailRecipients
	if len(recipients) > remaining {
		log.Printf("[alert] 邮件额度只剩 %d 封，本次只发给前 %d 个收件人（%s）",
			remaining, remaining, ev.Kind)
		recipients = recipients[:remaining]
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
	for _, to := range recipients {
		// 带上事件 ID：发件箱最终失败时可以回写这条告警，页面才不会谎报「已通知」。
		payload := map[string]any{"alert_event_id": ev.ID}
		if _, err := s.enqueueMail(to, subject, body, kind, payload, mailQuota{}); err != nil {
			log.Printf("[alert] 告警邮件入队失败（收件人 %s）: %v", maskEmail(to), err)
			continue
		}
		queued = true
	}
	return queued
}

// alertMailRemaining 返回本小时还能发多少封告警邮件。
// 统计失败时返回收件人上限：宁可多发一封，也不要因为一次查询失败把告警吞掉。
// 注意这里只收敛单次调用；多实例并发仍可能各发各的，已在 known-limits 登记。
func (s *Services) alertMailRemaining(limit int) int {
	if limit <= 0 {
		return maxNotifyRecipients
	}
	var n int64
	err := s.DB.Model(&model.MailOutbox{}).
		Where("kind IN ? AND created_at >= ?",
			[]string{model.MailKindAlertFiring, model.MailKindAlertResolved},
			time.Now().Add(-alertMailWindow)).
		Count(&n).Error
	if err != nil {
		log.Printf("[alert] 统计告警邮件数量失败，跳过限流: %v", err)
		return maxNotifyRecipients
	}
	remaining := limit - int(n)
	if remaining < 0 {
		remaining = 0
	}
	return remaining
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
		occ, start, end := s.dailyReportWindow(cfg, now)
		s.claimAndSendReport("daily", KeyReportDailyLastAt, occ, start, end, now)
	}
	if cfg.WeeklyEnabled {
		occ, start, end := s.weeklyReportWindow(cfg, now)
		s.claimAndSendReport("weekly", KeyReportWeeklyLastAt, occ, start, end, now)
	}
}

// dailyReportWindow 返回最近一期日报的「计划时刻」与统计区间。
// 区间按自然日对齐（计划时刻往前一整天）：流量这类日粒度数据不会把首尾两个日桶重复计入。
// 取「最近一期」而不是「今天这一期」，停机错过一次后仍能补发。
func (s *Services) dailyReportWindow(cfg ReportConfig, now time.Time) (time.Time, time.Time, time.Time) {
	occ := lastDailyOccurrence(now, cfg.DailyHour)
	end := time.Date(occ.Year(), occ.Month(), occ.Day(), 0, 0, 0, 0, occ.Location())
	return occ, end.AddDate(0, 0, -1), end
}

// weeklyReportWindow 取「最近一次到点的周报时刻」，因此停机错过一天也能补发。
func (s *Services) weeklyReportWindow(cfg ReportConfig, now time.Time) (time.Time, time.Time, time.Time) {
	occ := lastWeeklyOccurrence(now, cfg.WeeklyWeekday, cfg.WeeklyHour)
	end := time.Date(occ.Year(), occ.Month(), occ.Day(), 0, 0, 0, 0, occ.Location())
	return occ, end.AddDate(0, 0, -7), end
}

// lastDailyOccurrence 返回不晚于 now 的最近一个 hour:00。
func lastDailyOccurrence(now time.Time, hour int) time.Time {
	occ := time.Date(now.Year(), now.Month(), now.Day(), clampInt(hour, 0, 23), 0, 0, 0, now.Location())
	if occ.After(now) {
		occ = occ.AddDate(0, 0, -1)
	}
	return occ
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

// claimAndSendReport 用「把标记从上一期改成这一期」的方式跨实例认领报告期：
// 只有 CAS 成功的实例才发送，避免多实例同时读到旧标记后各发一封。
// 一封都没发出去时把标记退回，下一轮重试。
func (s *Services) claimAndSendReport(kind string, marker SettingKey, occurrence, start, end, now time.Time) {
	prev := s.Settings.Get(marker)
	next := occurrence.UTC().Format(time.RFC3339)
	if prev == next {
		// 这一期已经认领过。Postgres 把「值没变」也算作命中行，
		// 不加这个判断会每 5 分钟重发一次。
		return
	}
	claimed, err := s.Settings.CompareAndSwap(marker, prev, next)
	if err != nil {
		log.Printf("[report] 认领 %s 失败: %v", kind, err)
		return
	}
	if !claimed {
		return
	}
	if s.enqueueSummaryReport(s.ReportConfig(), kind, start, end, now) > 0 {
		log.Printf("[report] 已入队%s（%s ~ %s）", reportName(kind),
			start.Format("2006-01-02"), end.Format("2006-01-02"))
		return
	}
	if _, err := s.Settings.CompareAndSwap(marker, next, prev); err != nil {
		log.Printf("[report] 回滚 %s 认领失败: %v", kind, err)
	}
}

func reportName(kind string) string {
	if kind == "weekly" {
		return "周报"
	}
	return "日报"
}

// enqueueSummaryReport 生成并投递摘要邮件，返回成功入队的封数。
func (s *Services) enqueueSummaryReport(cfg ReportConfig, kind string, start, end, now time.Time) int {
	data := s.buildReportData(start, end, now)

	vars := map[string]string{
		"site_name":       s.Settings.Get(KeySiteName),
		"report_name":     reportName(kind),
		"period":          fmt.Sprintf("%s ~ %s", start.Format("2006-01-02"), end.Format("2006-01-02")),
		"generated_at":    now.Format("2006-01-02 15:04:05"),
		"users_total":     numOrUnknown(data.UsersOK, data.UsersTotal),
		"users_new":       numOrUnknown(data.UsersOK, data.UsersNew),
		"tunnels_total":   numOrUnknown(data.TunnelsOK, data.TunnelsTotal),
		"tunnels_online":  numOrUnknown(data.TunnelsOK, data.TunnelsOnline),
		"traffic":         data.trafficText(),
		"error_rate":      pctOrUnknown(data.MetricsOK, data.ErrorRateAvg, 2),
		"disk":            pctOrUnknown(data.MetricsOK, data.DiskPct, 1),
		"last_backup":     data.lastBackupText(),
		"alerts_firing":   numOrUnknown(data.AlertsOK, data.AlertsFiring),
		"alerts_resolved": numOrUnknown(data.AlertsOK, data.AlertsResolved),
		"alert_lines":     data.alertLines(),
	}

	subject, body := s.renderMail(MailEventReportSummary, vars)
	if subject == "" || body == "" {
		log.Printf("[report] 摘要邮件模板缺失，已跳过（%s）", kind)
		return 0
	}

	queued := 0
	for _, to := range cfg.Recipients {
		if _, err := s.enqueueMail(to, subject, body, model.MailKindReportSummary, nil, mailQuota{}); err != nil {
			log.Printf("[report] 摘要邮件入队失败（收件人 %s）: %v", maskEmail(to), err)
			continue
		}
		queued++
	}
	if queued > 0 {
		log.Printf("[report] 摘要邮件已入队（%s，%d 封）", reportName(kind), queued)
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

	// 查询失败时保持 false：摘要里显示「未知」，而不是把 0 当成真实统计。
	UsersOK   bool
	TunnelsOK bool
	TrafficOK bool
	AlertsOK  bool
	MetricsOK bool
	BackupOK  bool
}

func numOrUnknown(ok bool, v int64) string {
	if !ok {
		return "未知"
	}
	return fmt.Sprintf("%d", v)
}

func pctOrUnknown(ok bool, v float64, digits int) string {
	if !ok {
		return "未知"
	}
	return strconv.FormatFloat(v, 'f', digits, 64)
}

func (d reportData) trafficText() string {
	if !d.TrafficOK {
		return "未知"
	}
	return formatBytesCN(d.TrafficIn + d.TrafficOut)
}

func (d reportData) lastBackupText() string {
	if !d.BackupOK {
		return "未知"
	}
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

	d.UsersOK = true
	if err := db.Model(&model.User{}).Count(&d.UsersTotal).Error; err != nil {
		log.Printf("[report] 统计用户总数失败: %v", err)
		d.UsersOK = false
	}
	if err := db.Model(&model.User{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&d.UsersNew).Error; err != nil {
		log.Printf("[report] 统计新增用户失败: %v", err)
		d.UsersOK = false
	}

	d.TunnelsOK = true
	if err := db.Model(&model.Tunnel{}).Count(&d.TunnelsTotal).Error; err != nil {
		log.Printf("[report] 统计隧道总数失败: %v", err)
		d.TunnelsOK = false
	}
	var tunnels []model.Tunnel
	if err := db.Select("id", "status", "last_online_at").
		Where("status = ?", model.TunnelStatusActive).Find(&tunnels).Error; err != nil {
		log.Printf("[report] 读取隧道列表失败: %v", err)
		d.TunnelsOK = false
	} else {
		for i := range tunnels {
			if s.IsTunnelOnline(&tunnels[i]) {
				d.TunnelsOnline++
			}
		}
	}

	// 流量按日聚合：区间左闭右开，避免 24 小时窗口把首尾两个日桶都算进来。
	var traffic struct {
		InBytes  int64
		OutBytes int64
	}
	if err := db.Model(&model.TrafficDaily{}).
		Select("COALESCE(SUM(in_bytes),0) AS in_bytes, COALESCE(SUM(out_bytes),0) AS out_bytes").
		Where("date >= ? AND date < ?", start.Format("2006-01-02"), end.Format("2006-01-02")).
		Scan(&traffic).Error; err != nil {
		log.Printf("[report] 统计流量失败: %v", err)
	} else {
		d.TrafficIn, d.TrafficOut = traffic.InBytes, traffic.OutBytes
		d.TrafficOK = true
	}

	d.AlertsOK = true
	if err := db.Model(&model.AlertEvent{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&d.AlertsFiring).Error; err != nil {
		log.Printf("[report] 统计新增告警失败: %v", err)
		d.AlertsOK = false
	}
	if err := db.Model(&model.AlertEvent{}).
		Where("resolved_at >= ? AND resolved_at < ?", start, end).
		Count(&d.AlertsResolved).Error; err != nil {
		log.Printf("[report] 统计恢复告警失败: %v", err)
		d.AlertsOK = false
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
	} else {
		d.ErrorRateAvg, d.DiskPct = avg.Rate, avg.Disk
		d.MetricsOK = true
	}

	if hours, exists, ok := s.latestBackupAge(now); ok {
		d.BackupOK = true
		d.HasBackup, d.BackupHours = exists, hours
	}

	if err := db.Model(&model.AlertEvent{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Order("id DESC").Limit(5).Find(&d.Recent).Error; err != nil {
		log.Printf("[report] 读取告警摘要失败: %v", err)
	}
	return d
}
