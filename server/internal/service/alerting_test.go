package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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
