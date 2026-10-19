package service

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 健康分不是「一个看起来专业的数字」，而是把分散在几个页面的信号
// 压成一句「现在要不要处理」。因此每个分项都必须能落到一条具体动作上，
// 算不出来的分项标 unknown 并从加权里剔除，而不是给个 0 分冤枉人。

const certStatusTTL = 5 * time.Minute

var certStatusCache struct {
	mu     sync.Mutex
	at     time.Time
	status tlscfg.CertStatus
}

type HealthComponent struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Weight int    `json:"weight"`
	Status string `json:"status"` // ok / warn / critical / unknown
	Detail string `json:"detail"`
}

type HealthTodo struct {
	Key    string `json:"key"`
	Level  string `json:"level"` // critical / warning / info
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Link   string `json:"link,omitempty"`
}

type HealthReport struct {
	Score       int               `json:"score"`
	Grade       string            `json:"grade"`
	Components  []HealthComponent `json:"components"`
	Todos       []HealthTodo      `json:"todos"`
	GeneratedAt time.Time         `json:"generated_at"`
}

func (s *Services) HealthReport() HealthReport {
	components := make([]HealthComponent, 0, 4)
	todos := make([]HealthTodo, 0, 6)

	// 磁盘
	if latest := s.Monitor.Latest(); latest.DiskTotal > 0 {
		used := float64(latest.DiskUsed) / float64(latest.DiskTotal) * 100
		score := clampScore(100 - int(math.Max(0, used-50)*2))
		status := "ok"
		switch {
		case used >= 90:
			status = "critical"
		case used >= 75:
			status = "warn"
		}
		path := latest.DiskPath
		if path == "" {
			path = "/"
		}
		components = append(components, HealthComponent{
			Key: "disk", Name: "磁盘", Score: score, Weight: 35, Status: status,
			Detail: fmt.Sprintf("已用 %.1f%%（%s）", used, path),
		})
		if used >= 95 {
			todos = append(todos, HealthTodo{
				Key: "disk_critical", Level: "critical",
				Title:  "磁盘即将写满",
				Detail: fmt.Sprintf("当前使用率 %.1f%%，写满后数据库与证书续期都会失败", used),
			})
		} else if used >= 85 {
			todos = append(todos, HealthTodo{
				Key: "disk_high", Level: "warning",
				Title:  "磁盘使用率偏高",
				Detail: fmt.Sprintf("当前使用率 %.1f%%，建议清理日志与旧备份", used),
			})
		}
	} else {
		components = append(components, HealthComponent{
			Key: "disk", Name: "磁盘", Weight: 35, Status: "unknown", Detail: "尚未采集到磁盘信息",
		})
	}

	// 备份
	if !s.BackupSupported() {
		components = append(components, HealthComponent{
			Key: "backup", Name: "备份", Weight: 25, Status: "unknown", Detail: "当前数据库不支持面板内备份",
		})
	} else if hours, exists, ok := s.latestBackupAge(time.Now()); !ok {
		components = append(components, HealthComponent{
			Key: "backup", Name: "备份", Weight: 25, Status: "unknown", Detail: "读取备份目录失败",
		})
	} else if !exists {
		components = append(components, HealthComponent{
			Key: "backup", Name: "备份", Weight: 25, Score: 0, Status: "critical", Detail: "没有任何备份",
		})
		todos = append(todos, HealthTodo{
			Key: "backup_missing", Level: "critical",
			Title:  "还没有数据库备份",
			Detail: "数据库损坏时无法恢复，建议在「备份与恢复」里立即备份并开启自动备份",
			Link:   "/backups",
		})
	} else {
		score := 100
		if hours > 26 {
			score = clampScore(100 - int((hours-26)/142*100))
		}
		status := "ok"
		switch {
		case hours > 72:
			status = "critical"
		case hours > 30:
			status = "warn"
		}
		components = append(components, HealthComponent{
			Key: "backup", Name: "备份", Score: score, Weight: 25, Status: status,
			Detail: fmt.Sprintf("最近一次成功备份在 %.0f 小时前", hours),
		})
		if hours > 72 {
			todos = append(todos, HealthTodo{
				Key: "backup_stale", Level: "warning",
				Title:  "备份已过期",
				Detail: fmt.Sprintf("最近一次成功备份在 %.0f 小时前", hours),
				Link:   "/backups",
			})
		}
	}

	// 告警
	var firing, undelivered int64
	if err := s.DB.Model(&model.AlertEvent{}).
		Where("status = ?", model.AlertStatusFiring).Count(&firing).Error; err != nil {
		components = append(components, HealthComponent{
			Key: "alerts", Name: "告警", Weight: 25, Status: "unknown", Detail: "读取告警失败",
		})
	} else {
		score := 100
		status := "ok"
		switch {
		case firing >= 3:
			score, status = 0, "critical"
		case firing == 2:
			score, status = 40, "warn"
		case firing == 1:
			score, status = 70, "warn"
		}
		detail := "没有进行中的告警"
		if firing > 0 {
			detail = fmt.Sprintf("%d 条告警仍在进行中", firing)
			todos = append(todos, HealthTodo{
				Key: "alert_firing", Level: statusToLevel(status),
				Title:  "有告警未处理",
				Detail: detail,
				Link:   "/alerts",
			})
		}
		components = append(components, HealthComponent{
			Key: "alerts", Name: "告警", Score: score, Weight: 25, Status: status, Detail: detail,
		})
		if err := s.DB.Model(&model.AlertEvent{}).
			Where("status = ? AND delivered = ?", model.AlertStatusFiring, false).
			Count(&undelivered).Error; err == nil && undelivered > 0 {
			todos = append(todos, HealthTodo{
				Key: "alert_undelivered", Level: "warning",
				Title:  "告警没有送达",
				Detail: fmt.Sprintf("%d 条进行中的告警两个通道都没送达，检查 Webhook 与邮件配置", undelivered),
				Link:   "/alerts",
			})
		}
	}

	// 证书
	certs := s.cachedDomainCerts()
	if !certs.Available || len(certs.Certs) == 0 {
		components = append(components, HealthComponent{
			Key: "certs", Name: "证书", Weight: 15, Status: "unknown", Detail: "没有可读取的证书信息",
		})
	} else {
		minDays, minDomain := certs.Certs[0].DaysLeft, certs.Certs[0].Domain
		for _, c := range certs.Certs {
			if c.DaysLeft < minDays {
				minDays, minDomain = c.DaysLeft, c.Domain
			}
		}
		score := 100
		if minDays < 30 {
			score = clampScore(minDays * 100 / 30)
		}
		status := "ok"
		switch {
		case minDays <= 7:
			status = "critical"
		case minDays < 30:
			status = "warn"
		}
		components = append(components, HealthComponent{
			Key: "certs", Name: "证书", Score: score, Weight: 15, Status: status,
			Detail: fmt.Sprintf("最近到期：%s（%d 天）", minDomain, minDays),
		})
		if minDays < 30 {
			todos = append(todos, HealthTodo{
				Key: "cert_expiring", Level: statusToLevel(status),
				Title:  "证书即将到期",
				Detail: fmt.Sprintf("%s 还有 %d 天过期，续期失败会导致面板与隧道全部不可用", minDomain, minDays),
				Link:   "/domain",
			})
		}
	}

	// 配置层面的提醒
	cfg := s.AlertConfig()
	if !cfg.Enabled {
		todos = append(todos, HealthTodo{
			Key: "alert_disabled", Level: "info",
			Title:  "告警未启用",
			Detail: "出现故障时不会有任何通知",
			Link:   "/alerts",
		})
	} else if cfg.WebhookURL == "" && !cfg.EmailEnabled {
		todos = append(todos, HealthTodo{
			Key: "alert_no_channel", Level: "warning",
			Title:  "告警没有可用的通知通道",
			Detail: "Webhook 与邮件都没配置，告警只会留在面板里",
			Link:   "/alerts",
		})
	}
	if cfg.EmailEnabled && !s.MailEnabled() {
		todos = append(todos, HealthTodo{
			Key: "mail_not_ready", Level: "warning",
			Title:  "邮件通道未就绪",
			Detail: "已开启邮件通知或定时报告，但 SMTP 未配置/未启用，邮件不会发出",
			Link:   "/system",
		})
	}

	score := weightedScore(components)
	return HealthReport{
		Score:       score,
		Grade:       healthGrade(score),
		Components:  components,
		Todos:       todos,
		GeneratedAt: time.Now(),
	}
}

func (s *Services) cachedDomainCerts() tlscfg.CertStatus {
	certStatusCache.mu.Lock()
	defer certStatusCache.mu.Unlock()
	if !certStatusCache.at.IsZero() && time.Since(certStatusCache.at) < certStatusTTL {
		return certStatusCache.status
	}
	st, err := s.DomainCerts()
	if err != nil {
		st = tlscfg.CertStatus{Reason: err.Error()}
	}
	certStatusCache.at = time.Now()
	certStatusCache.status = st
	return st
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// weightedScore 只在「算得出来」的分项之间按权重归一，避免把未知项当成 0 分。
func weightedScore(components []HealthComponent) int {
	totalWeight, sum := 0, 0
	for _, c := range components {
		if c.Status == "unknown" {
			continue
		}
		totalWeight += c.Weight
		sum += c.Score * c.Weight
	}
	if totalWeight == 0 {
		return 0
	}
	return int(math.Round(float64(sum) / float64(totalWeight)))
}

func healthGrade(score int) string {
	switch {
	case score >= 90:
		return "优"
	case score >= 75:
		return "良"
	case score >= 60:
		return "中"
	default:
		return "差"
	}
}

func statusToLevel(status string) string {
	switch status {
	case "critical":
		return "critical"
	case "warn":
		return "warning"
	default:
		return "info"
	}
}
