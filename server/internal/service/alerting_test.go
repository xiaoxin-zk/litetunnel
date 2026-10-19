package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func alertSettingMap(webhook string, enabled bool) map[SettingKey]string {
	return map[SettingKey]string{
		KeyAlertEnabled:     boolText(enabled),
		KeyAlertWebhook:     webhook,
		KeyAlertErrorRate:   "5",
		KeyAlertDisk:        "90",
		KeyAlertBackupHours: "48",
	}
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestRaiseAlertRespectsCooldown(t *testing.T) {
	svc := newTestServices(t, nil)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	svc.raiseAlert("disk", "critical", "磁盘使用率 96%", 96, 90)

	var rows []model.AlertEvent
	if err := svc.DB.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("冷却窗口内同类告警只应记一条，实际 %d 条", len(rows))
	}
	if !rows[0].Delivered {
		t.Error("Webhook 返回 2xx 后应标记为已送达")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("冷却窗口内只应推送一次，实际 %d 次", got)
	}
}

func TestRaiseAlertMarksUndeliveredOnWebhookFailure(t *testing.T) {
	svc := newTestServices(t, nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}
	svc.raiseAlert("error_rate", "warning", "接口错误率 42%", 42, 5)

	var row model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&row).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if row.Delivered {
		t.Error("接收端返回 500 时不能标记为已送达，否则面板会误报推送成功")
	}
}

// Webhook 不该跟随 3xx：跳转目标没经过出站校验，跟随就等于绕过策略。
func TestRaiseAlertDoesNotFollowRedirect(t *testing.T) {
	svc := newTestServices(t, nil)

	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	if err := svc.UpdateSettings(alertSettingMap(redirector.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}
	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)

	var row model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&row).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if row.Delivered {
		t.Error("3xx 不是 2xx，不能标记为已送达")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("不能跟随重定向，实际打到了跳转目标 %d 次", got)
	}
}

// 一次网络抖动不该让运维等满 30 分钟冷却；重试同一条，别把历史表刷成重复行。
func TestRaiseAlertRetriesUndeliveredEventWithoutNewRow(t *testing.T) {
	svc := newTestServices(t, nil)

	var recovered atomic.Bool
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if recovered.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	recovered.Store(true)
	svc.raiseAlert("disk", "critical", "磁盘使用率 96%", 96, 90)

	var rows []model.AlertEvent
	if err := svc.DB.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("冷却窗口内重试不该新增记录，实际 %d 条", len(rows))
	}
	if !rows[0].Delivered {
		t.Error("重试成功后应标记为已送达")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("应推送两次（失败一次、重试一次），实际 %d 次", got)
	}
}

func TestRunAlertCyclePrunesOldSamples(t *testing.T) {
	svc := newTestServices(t, nil)

	now := time.Now()
	old := model.MetricSample{At: now.Add(-15 * 24 * time.Hour), Requests: 10}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("写入过期样本失败: %v", err)
	}

	svc.runAlertCycle(now)

	var kept []model.MetricSample
	if err := svc.DB.Order("sampled_at ASC").Find(&kept).Error; err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("14 天前的样本应被清理，实际剩余 %d 条", len(kept))
	}
	if kept[0].ID == old.ID {
		t.Error("保留下来的不该是过期样本")
	}
}

// 记录 Webhook 收到的 payload，供生命周期断言使用。
type alertSink struct {
	mu       sync.Mutex
	payloads []map[string]any
}

func (s *alertSink) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		s.mu.Lock()
		s.payloads = append(s.payloads, p)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *alertSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.payloads)
}

func (s *alertSink) at(i int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.payloads[i]
}

// 条件恢复后事件必须被标成 resolved 并推一条恢复通知；重复调用不能再推。
func TestAlertLifecycleResolveAndNotify(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)
	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	svc.resolveAlert("disk", "磁盘使用率已回落至 70%")

	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if ev.Status != model.AlertStatusResolved {
		t.Fatalf("状态 = %q，期望 resolved", ev.Status)
	}
	if ev.ResolvedAt == nil {
		t.Fatal("恢复时间不能为空")
	}
	if !ev.ResolvedNotified {
		t.Error("恢复通知送达后应标记 resolved_notified")
	}
	if got := sink.count(); got != 2 {
		t.Fatalf("应推送触发 + 恢复两条，实际 %d 条", got)
	}
	if status := sink.at(0)["status"]; status != model.AlertStatusFiring {
		t.Errorf("第一条应是 firing，实际 %v", status)
	}
	if status := sink.at(1)["status"]; status != model.AlertStatusResolved {
		t.Errorf("第二条应是 resolved，实际 %v", status)
	}

	svc.resolveAlert("disk", "磁盘使用率已回落至 70%")
	if got := sink.count(); got != 2 {
		t.Errorf("重复恢复不该再推送，实际累计 %d 条", got)
	}
}

// 两台实例各自采样：A 的故障不能被 B 的正常样本「恢复」。
func TestAlertEventsAreScopedPerInstance(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)
	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "A 实例磁盘 95%", 95, 90)
	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if ev.Instance != svc.nodeID {
		t.Fatalf("事件归属 = %q，期望 %q", ev.Instance, svc.nodeID)
	}

	// 模拟另一台实例的正常采样：它不应该动到这条事件。
	orig := svc.nodeID
	svc.nodeID = "other-host@0.0.0.0:7848"
	svc.resolveAlert("disk", "B 实例磁盘正常")
	svc.nodeID = orig

	if err := svc.DB.First(&ev, ev.ID).Error; err != nil {
		t.Fatalf("重新读取告警失败: %v", err)
	}
	if ev.Status != model.AlertStatusFiring {
		t.Fatalf("另一实例不该恢复本实例的事件，状态 = %q", ev.Status)
	}
}

// 自动恢复后短时间复发，视为同一次抖动：重开原事件，不新增行、不补发通知。
func TestAlertReopensSilentlyWithinCooldown(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)
	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	svc.resolveAlert("disk", "磁盘使用率已回落至 70%")

	var first model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&first).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 96%", 96, 90)

	var rows []model.AlertEvent
	if err := svc.DB.Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("冷却窗口内复发应重开原事件，实际 %d 条", len(rows))
	}
	if rows[0].ID != first.ID {
		t.Errorf("事件 ID 变了：%d → %d", first.ID, rows[0].ID)
	}
	if rows[0].Status != model.AlertStatusFiring {
		t.Errorf("复发后状态 = %q，期望 firing", rows[0].Status)
	}
	if rows[0].ResolvedAt != nil {
		t.Error("重开后恢复时间应清空")
	}
	if rows[0].ResolvedNotified {
		t.Error("重开后应清掉「恢复已通知」，否则下一次恢复永远不会再尝试")
	}
	if got := sink.count(); got != 2 {
		t.Errorf("静默重开不该补发通知，实际累计 %d 条", got)
	}
}

// 手动解决是「有记录的静默」：冷却内不再打扰，冷却后条件仍在才开新事件。
func TestManualResolveSuppressesRepeatUntilCooldown(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)
	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if err := svc.ResolveAlertEvent(ev.ID); err != nil {
		t.Fatalf("手动解决失败: %v", err)
	}
	if err := svc.ResolveAlertEvent(ev.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("重复解决应返回未找到，实际 %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 96%", 96, 90)

	var rows []model.AlertEvent
	if err := svc.DB.Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("冷却内手动解决应保持静默，实际 %d 条", len(rows))
	}
	if rows[0].Status != model.AlertStatusManualResolved {
		t.Errorf("状态 = %q，期望 manual_resolved", rows[0].Status)
	}

	// 冷却过去后条件仍在：应该开一条新事件。
	if err := svc.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).
		Update("resolved_at", time.Now().Add(-2*alertCooldown)).Error; err != nil {
		t.Fatalf("调整恢复时间失败: %v", err)
	}
	svc.raiseAlert("disk", "critical", "磁盘使用率 97%", 97, 90)

	rows = nil
	if err := svc.DB.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("冷却后应开新事件，实际 %d 条", len(rows))
	}
	if rows[1].Status != model.AlertStatusFiring {
		t.Errorf("新事件状态 = %q，期望 firing", rows[1].Status)
	}
}

// 长期故障不能只在开头响一声：同一事件每 30 分钟提醒一次，并带上最新读数。
func TestRaiseAlertRemindsEveryCooldown(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)
	if err := svc.UpdateSettings(alertSettingMap(srv.URL, true)); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)

	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if err := svc.DB.Model(&model.AlertEvent{}).Where("id = ?", ev.ID).
		Update("last_notified_at", time.Now().Add(-alertCooldown-time.Minute)).Error; err != nil {
		t.Fatalf("调整提醒时间失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 97%", 97, 90)

	var rows []model.AlertEvent
	if err := svc.DB.Find(&rows).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("提醒不该新增事件，实际 %d 条", len(rows))
	}
	if rows[0].Message != "磁盘使用率 97%" {
		t.Errorf("提醒应带上最新读数，实际 %q", rows[0].Message)
	}
	if got := sink.count(); got != 2 {
		t.Errorf("应推送触发 + 提醒两条，实际 %d 条", got)
	}
}

// 数据不足时不能把正在响的告警误判成恢复：
// 面板刚启动、监控还没采到磁盘读数，DiskTotal 为 0，看着像「磁盘 0%」。
func TestRunAlertCycleKeepsFiringWhenDataUnavailable(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)

	settings := alertSettingMap(srv.URL, true)
	settings[KeyAlertDisk] = "1"
	settings[KeyAlertErrorRate] = "0"
	settings[KeyAlertBackupHours] = "0"
	if err := svc.UpdateSettings(settings); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	svc.raiseAlert("disk", "critical", "磁盘使用率 95%", 95, 90)
	svc.runAlertCycle(time.Now()) // Monitor 还没有磁盘读数

	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if ev.Status != model.AlertStatusFiring {
		t.Fatalf("读数未知时不该自动恢复，状态 = %q", ev.Status)
	}
	if got := sink.count(); got != 1 {
		t.Errorf("读数未知时不该推恢复通知，实际累计 %d 条", got)
	}
}

// 走完整一轮采样：条件真正消失时，事件要自动恢复并推送恢复通知。
func TestRunAlertCycleResolvesWhenConditionClears(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)

	settings := alertSettingMap(srv.URL, true)
	settings[KeyAlertDisk] = "0" // 关掉另外两条规则，避免干扰断言
	settings[KeyAlertErrorRate] = "0"
	settings[KeyAlertBackupHours] = "1"
	if err := svc.UpdateSettings(settings); err != nil {
		t.Fatalf("保存告警设置失败: %v", err)
	}

	// 先造一条「备份超时」告警，再补一份新备份，让条件自行消失。
	svc.raiseAlert("backup_stale", "warning", "已有 99 小时没有成功备份", 99, 1)
	if _, err := svc.CreateBackup(""); err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}

	svc.runAlertCycle(time.Now())

	var ev model.AlertEvent
	if err := svc.DB.Order("id DESC").First(&ev).Error; err != nil {
		t.Fatalf("读取告警失败: %v", err)
	}
	if ev.Status != model.AlertStatusResolved {
		t.Fatalf("条件不再命中后状态 = %q，期望 resolved", ev.Status)
	}
	if !ev.ResolvedNotified {
		t.Error("应推送恢复通知并标记 resolved_notified")
	}
	if got := sink.count(); got != 2 {
		t.Errorf("应推送触发 + 恢复两条，实际 %d 条", got)
	}
}

// 持续判定：只有连续 N 个窗口都超标才触发；恢复不受影响。
func TestSustainedRequiresConsecutiveWindows(t *testing.T) {
	svc := newTestServices(t, nil)
	now := time.Now()
	cfg := AlertConfig{ErrorRatePct: 5, SustainedWindows: 2}
	stats := middleware.HTTPStatsSnapshot{Total: 100, Errors: 20}
	cur := model.MetricSample{
		At: now, Requests: 100, Errors: 20, ErrorRate: 20, Instance: svc.nodeID,
	}
	if err := svc.DB.Create(&cur).Error; err != nil {
		t.Fatalf("写入当前样本失败: %v", err)
	}

	checks := svc.evaluateAlerts(cfg, cur, stats, false, now)
	if len(checks) != 1 {
		t.Fatalf("应只有一条规则参与评估，实际 %d 条", len(checks))
	}
	if !checks[0].breaching {
		t.Error("当前窗口错误率 20% 应判为超标")
	}
	if checks[0].fire {
		t.Error("只有 1 个窗口超标时不该触发（要求连续 2 个）")
	}

	prev := model.MetricSample{
		At: now.Add(-alertInterval), Requests: 100, Errors: 20, ErrorRate: 20, Instance: svc.nodeID,
	}
	if err := svc.DB.Create(&prev).Error; err != nil {
		t.Fatalf("写入上一窗口样本失败: %v", err)
	}
	checks = svc.evaluateAlerts(cfg, cur, stats, false, now)
	if !checks[0].fire {
		t.Error("连续两个窗口都超标后应触发")
	}

	// 横跨停机时间的样本不能算「连续」，否则重启后会拿停机前的数据凑数。
	if err := svc.DB.Where("1 = 1").Delete(&model.MetricSample{}).Error; err != nil {
		t.Fatalf("清理样本失败: %v", err)
	}
	stale := model.MetricSample{
		At: now.Add(-3 * time.Hour), Requests: 100, Errors: 20, ErrorRate: 20, Instance: svc.nodeID,
	}
	if err := svc.DB.Create(&stale).Error; err != nil {
		t.Fatalf("写入陈旧样本失败: %v", err)
	}
	if err := svc.DB.Create(&model.MetricSample{
		At: now, Requests: 100, Errors: 20, ErrorRate: 20, Instance: svc.nodeID,
	}).Error; err != nil {
		t.Fatalf("写入当前样本失败: %v", err)
	}
	checks = svc.evaluateAlerts(cfg, cur, stats, false, now)
	if checks[0].fire {
		t.Error("横跨停机的样本不该算连续")
	}
}

// 静默期间不新建告警、不推送；结束静默后问题仍在才补一条。
func TestSilenceSuppressesNewAlerts(t *testing.T) {
	svc := newTestServices(t, nil)
	sink := &alertSink{}
	srv := sink.server(t)

	settings := alertSettingMap(srv.URL, true)
	settings[KeyAlertDisk] = "0"
	settings[KeyAlertErrorRate] = "0"
	settings[KeyAlertBackupHours] = "1"
	settings[KeyAlertSilenceUntil] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	settings[KeyAlertSilenceReason] = "数据库维护"
	if err := svc.UpdateSettings(settings); err != nil {
		t.Fatalf("保存静默设置失败: %v", err)
	}

	svc.runAlertCycle(time.Now())

	var count int64
	if err := svc.DB.Model(&model.AlertEvent{}).Count(&count).Error; err != nil {
		t.Fatalf("统计告警失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("静默期间不该新建告警，实际 %d 条", count)
	}
	if got := sink.count(); got != 0 {
		t.Fatalf("静默期间不该推送，实际 %d 条", got)
	}

	if err := svc.UpdateSettings(map[SettingKey]string{KeyAlertSilenceUntil: ""}); err != nil {
		t.Fatalf("结束静默失败: %v", err)
	}
	svc.runAlertCycle(time.Now())

	if err := svc.DB.Model(&model.AlertEvent{}).Count(&count).Error; err != nil {
		t.Fatalf("统计告警失败: %v", err)
	}
	if count != 1 {
		t.Fatalf("结束静默后应补一条告警，实际 %d 条", count)
	}
	if got := sink.count(); got != 1 {
		t.Errorf("结束静默后应推送一条，实际 %d 条", got)
	}
}

func TestAlertSustainedAndSilenceValidation(t *testing.T) {
	svc := newTestServices(t, nil)
	base := alertSettingMap("http://127.0.0.1:9/hook", false)

	merge := func(extra map[SettingKey]string) map[SettingKey]string {
		out := make(map[SettingKey]string, len(base)+len(extra))
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	for _, extra := range []map[SettingKey]string{
		{KeyAlertSustained: "0"},
		{KeyAlertSustained: "13"},
		{KeyAlertSilenceUntil: "tomorrow"},
		{KeyAlertSilenceUntil: time.Now().AddDate(2, 0, 0).Format(time.RFC3339)},
		{KeyAlertSilenceReason: strings.Repeat("长", 201)},
	} {
		if err := svc.UpdateSettings(merge(extra)); err == nil {
			t.Errorf("%v 应被拒绝", extra)
		}
	}

	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := svc.UpdateSettings(merge(map[SettingKey]string{
		KeyAlertSustained:     "3",
		KeyAlertSilenceUntil:  until,
		KeyAlertSilenceReason: "维护",
	})); err != nil {
		t.Fatalf("合法配置不该被拒绝: %v", err)
	}
	cfg := svc.AlertConfig()
	if cfg.SustainedWindows != 3 {
		t.Errorf("持续窗口 = %d，期望 3", cfg.SustainedWindows)
	}
	if !cfg.Silenced(time.Now()) {
		t.Error("应处于静默窗口内")
	}
	if cfg.Silenced(time.Now().Add(2 * time.Hour)) {
		t.Error("静默时间过后不该仍判定为静默")
	}
}

func TestAlertEnabledRequiresWebhook(t *testing.T) {
	svc := newTestServices(t, nil)

	err := svc.UpdateSettings(map[SettingKey]string{
		KeyAlertEnabled: "true",
		KeyAlertWebhook: "",
	})
	if err == nil {
		t.Fatal("启用告警但没有 Webhook 地址时必须拒绝保存，否则告警会被静默丢弃")
	}
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("应返回参数错误，实际 %v", err)
	}
}

func TestTestAlertWebhookNeedsURL(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.TestAlertWebhook(); err == nil {
		t.Fatal("未配置 Webhook 时测试推送应直接报错")
	}
}
