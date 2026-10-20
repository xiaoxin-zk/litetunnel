package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 定时报告的调度与认领：决定「这一期该不该发」，并保证多实例只有一个发送者。

const (
	reportCheckInterval = 5 * time.Minute

	// 报告期认领租约：进程在「标记已认领」和「写入发件箱」之间退出时，
	// 租约到期后下一轮可以重新认领，避免整期报告永久丢失。
	reportClaimLease = 10 * time.Minute
)

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

// reportClaim 是设置表里报告标记的结构：`期次/租约到期时间`。
// 没有租约表示这一期已经发完；租约未到期表示有实例正在发。
type reportClaim struct {
	Period time.Time
	Lease  time.Time
}

func parseReportClaim(raw string) reportClaim {
	parts := strings.SplitN(strings.TrimSpace(raw), "/", 2)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return reportClaim{}
	}
	period, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[0]))
	if err != nil {
		return reportClaim{}
	}
	c := reportClaim{Period: period}
	if len(parts) == 2 {
		if lease, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[1])); err == nil {
			c.Lease = lease
		}
	}
	return c
}

func formatReportClaim(c reportClaim) string {
	if c.Period.IsZero() {
		return ""
	}
	base := c.Period.UTC().Format(time.RFC3339)
	if c.Lease.IsZero() {
		return base + "/"
	}
	return base + "/" + c.Lease.UTC().Format(time.RFC3339)
}

// claimAndSendReport 用「带租约的 CAS」跨实例认领报告期：
// 只有抢到的实例才发送；进程在发送前退出时，租约过期后会自动重试，
// 不会因为标记已经推进而永久漏掉这一期。
func (s *Services) claimAndSendReport(kind string, marker SettingKey, occurrence, start, end, now time.Time) {
	prevRaw := s.Settings.Get(marker)
	prev := parseReportClaim(prevRaw)
	if prev.Period.After(occurrence) {
		return // 已经发过更新的一期（时钟回拨等），不要倒退
	}
	if prev.Period.Equal(occurrence) && (prev.Lease.IsZero() || now.Before(prev.Lease)) {
		return // 已完成，或别的实例正在发
	}

	next := formatReportClaim(reportClaim{Period: occurrence, Lease: now.Add(reportClaimLease)})
	claimed, err := s.Settings.CompareAndSwap(marker, prevRaw, next)
	if err != nil {
		log.Printf("[report] 认领 %s 失败: %v", kind, err)
		return
	}
	if !claimed {
		return
	}

	if s.enqueueSummaryReport(s.ReportConfig(), kind, start, end, now) > 0 {
		done := formatReportClaim(reportClaim{Period: occurrence})
		if _, err := s.Settings.CompareAndSwap(marker, next, done); err != nil {
			log.Printf("[report] 标记 %s 完成失败（租约到期后可能重发）: %v", kind, err)
		}
		log.Printf("[report] 已入队%s（%s ~ %s）", reportName(kind),
			start.Format("2006-01-02"), end.Format("2006-01-02"))
		return
	}
	if _, err := s.Settings.CompareAndSwap(marker, next, prevRaw); err != nil {
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
