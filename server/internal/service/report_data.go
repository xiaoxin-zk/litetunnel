package service

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 报表数据的查询与格式化：只读聚合，任何一项失败都退化成「未知」，
// 不让一份摘要邮件因为某个次要统计失败而整体发不出去。

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

// buildReportData 汇总统计区间内的数据。
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
