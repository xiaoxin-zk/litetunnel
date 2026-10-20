package service

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 告警邮件通道：复用现有发件箱的重试/租约/失败上限，这里只负责
// 「什么时候发、发给谁、正文写什么」以及每小时的封数限流。

const (
	maxNotifyRecipients = 10
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

	phase := "firing"
	if resolved {
		phase = "resolved"
	}
	queued := false
	for _, to := range recipients {
		// 带上事件 ID 与阶段：发件箱最终失败时回写到对应的字段，
		// 页面才不会把「入队」或「失败」当成「已通知」。
		payload := map[string]any{"alert_event_id": ev.ID, "phase": phase}
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
