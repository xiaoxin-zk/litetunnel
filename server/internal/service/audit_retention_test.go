package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestAuditRetentionSettingBounds(t *testing.T) {
	svc := newTestServices(t, nil)
	if got := svc.Settings.Int(KeyAuditRetentionDays); got != 180 {
		t.Fatalf("默认保留期应为 180 天，实际 %d", got)
	}

	for _, bad := range []string{"-1", "3651", "abc"} {
		if err := svc.UpdateSettings(map[SettingKey]string{KeyAuditRetentionDays: bad}); !errors.Is(err, ErrInvalidParam) {
			t.Fatalf("保留期 %q 应被拒绝，实际 %v", bad, err)
		}
	}

	if err := svc.UpdateSettings(map[SettingKey]string{KeyAuditRetentionDays: "0"}); err != nil {
		t.Fatalf("0 表示永久保留，应保存成功: %v", err)
	}
}

func TestAuditRetentionPrune(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.UpdateSettings(map[SettingKey]string{KeyAuditRetentionDays: "30"}); err != nil {
		t.Fatalf("保存保留期失败: %v", err)
	}

	old := model.AuditLog{AdminName: "admin", Action: "test.old"}
	fresh := model.AuditLog{AdminName: "admin", Action: "test.fresh"}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("写入旧日志失败: %v", err)
	}
	if err := svc.DB.Create(&fresh).Error; err != nil {
		t.Fatalf("写入新日志失败: %v", err)
	}
	if err := svc.DB.Model(&model.AuditLog{}).Where("id = ?", old.ID).
		UpdateColumn("created_at", time.Now().AddDate(0, 0, -40)).Error; err != nil {
		t.Fatalf("回填旧日志时间失败: %v", err)
	}

	svc.RunMaintenance()

	var n int64
	if err := svc.DB.Model(&model.AuditLog{}).Where("id = ?", old.ID).Count(&n).Error; err != nil {
		t.Fatalf("统计旧日志失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("超过保留期的审计日志应被清理，实际仍在")
	}
	if err := svc.DB.Model(&model.AuditLog{}).Where("id = ?", fresh.ID).Count(&n).Error; err != nil {
		t.Fatalf("统计新日志失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("保留期内的审计日志不该被清理")
	}
}

func TestAuditRetentionZeroKeepsForever(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.UpdateSettings(map[SettingKey]string{KeyAuditRetentionDays: "0"}); err != nil {
		t.Fatalf("保存保留期失败: %v", err)
	}

	old := model.AuditLog{AdminName: "admin", Action: "test.forever"}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("写入日志失败: %v", err)
	}
	if err := svc.DB.Model(&model.AuditLog{}).Where("id = ?", old.ID).
		UpdateColumn("created_at", time.Now().AddDate(-5, 0, 0)).Error; err != nil {
		t.Fatalf("回填时间失败: %v", err)
	}

	svc.RunMaintenance()

	var n int64
	if err := svc.DB.Model(&model.AuditLog{}).Where("id = ?", old.ID).Count(&n).Error; err != nil {
		t.Fatalf("统计日志失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("保留期为 0 时审计日志应永久保留，实际被清理")
	}
}
