package service

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func countMailKind(t *testing.T, svc *Services, kind string) int64 {
	t.Helper()
	var n int64
	if err := svc.DB.Model(&model.MailOutbox{}).Where("kind = ?", kind).Count(&n).Error; err != nil {
		t.Fatalf("统计邮件失败: %v", err)
	}
	return n
}

func alertMailSettings(extra map[SettingKey]string) map[SettingKey]string {
	base := map[SettingKey]string{
		KeyAlertEnabled:        "true",
		KeyAlertErrorRate:      "0",
		KeyAlertDisk:           "0",
		KeyAlertBackupHours:    "0",
		KeyAlertEmailEnabled:   "true",
		KeyAlertEmailTo:        "ops@example.com",
		KeyAlertEmailMinLevel:  "warning",
		KeyAlertEmailHourlyMax: "10",
		KeyAlertEmailRecovery:  "true",
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// 邮件通道与 Webhook 独立：只配邮件也能收到告警，且事件应算「已通知」。
func TestAlertEmailEnqueuesAndCountsAsDelivered(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.UpdateSettings(alertMailSettings(nil)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("backup_stale", "warning", "已有 99 小时没有成功备份", 99, 1)

	var mails []model.MailOutbox
	if err := svc.DB.Where("kind = ?", model.MailKindAlertFiring).Find(&mails).Error; err != nil {
		t.Fatalf("读取发件箱失败: %v", err)
	}
	if len(mails) != 1 {
		t.Fatalf("应入队 1 封告警邮件，实际 %d 封", len(mails))
	}
	if mails[0].To != "ops@example.com" {
		t.Errorf("收件人 = %q", mails[0].To)
	}
	if !strings.Contains(mails[0].Body, "备份超时") {
		t.Errorf("正文应渲染出告警类型，实际 %q", mails[0].Body)
	}

	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if !ev.MailQueued {
		t.Error("邮件入队后应标记 mail_queued")
	}
	if ev.Delivered {
		t.Error("只入队、没有 Webhook 2xx 时不该标记 delivered")
	}
}

func TestAlertEmailHonorsLevelAndHourlyLimit(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.UpdateSettings(alertMailSettings(map[SettingKey]string{
		KeyAlertEmailMinLevel:  "critical",
		KeyAlertEmailHourlyMax: "1",
	})); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("error_rate", "warning", "警告级不该发邮件", 10, 5)
	if n := countMailKind(t, svc, model.MailKindAlertFiring); n != 0 {
		t.Fatalf("低于最低级别的告警不该发邮件，实际 %d 封", n)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	if n := countMailKind(t, svc, model.MailKindAlertFiring); n != 1 {
		t.Fatalf("严重级应发 1 封，实际 %d 封", n)
	}

	svc.raiseAlert("backup_stale", "critical", "备份超时", 99, 1)
	if n := countMailKind(t, svc, model.MailKindAlertFiring); n != 1 {
		t.Errorf("达到每小时上限后不该继续发，实际 %d 封", n)
	}
}

func TestAlertResolvedEmailRespectsToggle(t *testing.T) {
	for _, include := range []bool{true, false} {
		svc := newTestServices(t, nil)
		enableTestMail(t, svc)
		if err := svc.UpdateSettings(alertMailSettings(map[SettingKey]string{
			KeyAlertEmailRecovery: strconv.FormatBool(include),
		})); err != nil {
			t.Fatalf("保存告警设置失败: %v", err)
		}

		svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
		svc.resolveAlert("disk", "磁盘使用率已回落至 70%")

		n := countMailKind(t, svc, model.MailKindAlertResolved)
		if include && n != 1 {
			t.Errorf("开启恢复通知时应发 1 封，实际 %d 封", n)
		}
		if !include && n != 0 {
			t.Errorf("关闭恢复通知时不该发，实际 %d 封", n)
		}
	}
}

// 通知类邮件送达即终态，不应再走凭据激活流程。
func TestNotificationMailFinishesWithoutActivation(t *testing.T) {
	svc, fm := newMailTestServices(t)
	if _, err := svc.enqueueMail("ops@example.com", "s", "body",
		model.MailKindAlertFiring, nil, mailQuota{}); err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	deliverAll(svc)

	if fm.sentCount() != 1 {
		t.Fatalf("应发出 1 封，实际 %d 封", fm.sentCount())
	}
	var row model.MailOutbox
	if err := svc.DB.Where("kind = ?", model.MailKindAlertFiring).First(&row).Error; err != nil {
		t.Fatalf("读取发件箱失败: %v", err)
	}
	if row.Status != model.MailSent {
		t.Fatalf("状态 = %q，期望 sent（通知邮件没有激活步骤）", row.Status)
	}
	if row.Body != "" || row.Payload != "" {
		t.Error("送达后应清空正文与参数")
	}
}

// 发件箱最终失败时必须清掉 queued，否则下一轮提醒会以为「已入队」而不再重试。
func TestAlertMailFinalFailureClearsQueued(t *testing.T) {
	svc := newTestServices(t, nil)
	ev := model.AlertEvent{
		Kind: "disk", Level: "critical", Message: "磁盘 95%",
		Status: model.AlertStatusFiring, MailQueued: true, Instance: svc.nodeID,
	}
	if err := svc.DB.Create(&ev).Error; err != nil {
		t.Fatalf("写入告警失败: %v", err)
	}

	svc.noteAlertMailFailed(model.MailOutbox{
		Kind:    model.MailKindAlertFiring,
		Payload: fmt.Sprintf(`{"alert_event_id":%d}`, ev.ID),
	})
	if err := svc.DB.First(&ev, ev.ID).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if ev.MailQueued {
		t.Error("最终失败后必须清掉 mail_queued，否则提醒不会再发邮件")
	}
	if !ev.MailFailed {
		t.Error("最终失败后应标记 mail_failed")
	}

	// 恢复邮件走独立字段，不能污染触发状态。
	ev.MailFailed = false
	if err := svc.DB.Model(&ev).Update("mail_failed", false).Error; err != nil {
		t.Fatalf("重置失败: %v", err)
	}
	svc.noteAlertMailFailed(model.MailOutbox{
		Kind:    model.MailKindAlertResolved,
		Payload: fmt.Sprintf(`{"alert_event_id":%d,"phase":"resolved"}`, ev.ID),
	})
	if err := svc.DB.First(&ev, ev.ID).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if !ev.ResolvedMailFailed || ev.ResolvedMailQueued {
		t.Errorf("恢复邮件失败应记在 resolved 字段，实际 queued=%v failed=%v",
			ev.ResolvedMailQueued, ev.ResolvedMailFailed)
	}
	if ev.MailFailed {
		t.Error("恢复邮件失败不该影响触发邮件的状态")
	}
}

// 认领后进程崩溃：租约到期前不重发，到期后能自动补发。
func TestReportClaimLeaseRecoversAfterCrash(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.UpdateSettings(map[SettingKey]string{
		KeyAlertEmailTo:        "ops@example.com",
		KeyReportEnabled:       "true",
		KeyReportDailyEnabled:  "true",
		KeyReportDailyHour:     "9",
		KeyReportWeeklyEnabled: "false",
	}); err != nil {
		t.Fatalf("保存报告设置失败: %v", err)
	}

	now := time.Date(2026, 10, 20, 9, 30, 0, 0, time.Local)
	occurrence := lastDailyOccurrence(now, 9)

	// 模拟「已认领但进程在写发件箱前退出」：租约还在。
	claim := formatReportClaim(reportClaim{Period: occurrence, Lease: now.Add(5 * time.Minute)})
	if err := svc.Settings.SetInternal(map[SettingKey]string{KeyReportDailyLastAt: claim}); err != nil {
		t.Fatalf("写入认领标记失败: %v", err)
	}
	svc.runDueReports(now)
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 0 {
		t.Fatalf("租约未到期不该重发，实际 %d 封", n)
	}

	// 租约过期：上一轮显然已经挂了，应当补发。
	expired := formatReportClaim(reportClaim{Period: occurrence, Lease: now.Add(-time.Minute)})
	if err := svc.Settings.SetInternal(map[SettingKey]string{KeyReportDailyLastAt: expired}); err != nil {
		t.Fatalf("写入过期认领失败: %v", err)
	}
	svc.runDueReports(now)
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 1 {
		t.Fatalf("租约过期后应补发 1 封，实际 %d 封", n)
	}
}

func TestDailyReportEnqueuedOncePerDay(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.UpdateSettings(map[SettingKey]string{
		KeyAlertEmailTo:        "ops@example.com",
		KeyReportEnabled:       "true",
		KeyReportDailyEnabled:  "true",
		KeyReportDailyHour:     "9",
		KeyReportWeeklyEnabled: "false",
	}); err != nil {
		t.Fatalf("保存报告设置失败: %v", err)
	}

	now := time.Date(2026, 10, 20, 9, 30, 0, 0, time.Local)
	svc.runDueReports(now)
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 1 {
		t.Fatalf("应入队 1 封日报，实际 %d 封", n)
	}

	svc.runDueReports(now.Add(10 * time.Minute))
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 1 {
		t.Errorf("同一天不该重复发送，实际 %d 封", n)
	}

	svc.runDueReports(now.AddDate(0, 0, 1))
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 2 {
		t.Errorf("次日应再发一封，实际 %d 封", n)
	}
}

func TestWeeklyReportUsesMostRecentOccurrence(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.UpdateSettings(map[SettingKey]string{
		KeyAlertEmailTo:        "ops@example.com",
		KeyReportEnabled:       "true",
		KeyReportDailyEnabled:  "false",
		KeyReportWeeklyEnabled: "true",
		KeyReportWeeklyWeekday: "1", // 周一
		KeyReportWeeklyHour:    "9",
	}); err != nil {
		t.Fatalf("保存报告设置失败: %v", err)
	}

	// 2026-10-20 是周二；本周一 9:00 已过，应补发一期。
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.Local)
	svc.runDueReports(now)
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 1 {
		t.Fatalf("应补发 1 封周报，实际 %d 封", n)
	}
	svc.runDueReports(now.Add(time.Hour))
	if n := countMailKind(t, svc, model.MailKindReportSummary); n != 1 {
		t.Errorf("同一周不该重复发送，实际 %d 封", n)
	}
}

func TestHealthReportFlagsMissingBackupAndFiringAlert(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.DB.Create(&model.AlertEvent{
		Kind: "disk", Level: "critical", Message: "磁盘使用率 95%",
		Status: model.AlertStatusFiring,
	}).Error; err != nil {
		t.Fatalf("写入告警失败: %v", err)
	}

	rep := svc.HealthReport()
	if rep.Score < 0 || rep.Score > 100 {
		t.Fatalf("健康分越界: %d", rep.Score)
	}
	if rep.Grade == "" {
		t.Error("健康等级不能为空")
	}

	byKey := make(map[string]HealthComponent, len(rep.Components))
	for _, c := range rep.Components {
		byKey[c.Key] = c
	}
	if c, ok := byKey["backup"]; !ok || c.Status != "critical" {
		t.Errorf("没有备份时备份分项应为 critical，实际 %+v", c)
	}
	if c, ok := byKey["alerts"]; !ok || c.Score >= 100 {
		t.Errorf("有进行中告警时告警分项应扣分，实际 %+v", c)
	}

	todos := make(map[string]bool, len(rep.Todos))
	for _, td := range rep.Todos {
		todos[td.Key] = true
	}
	if !todos["backup_missing"] {
		t.Error("应给出「还没有备份」待办")
	}
	if !todos["alert_firing"] {
		t.Error("应给出「告警未处理」待办")
	}
}
