package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func enableAdminTOTP(t *testing.T, svc *Services, adminID uint) string {
	t.Helper()
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("生成 TOTP 密钥失败: %v", err)
	}
	if err := svc.DB.Model(&model.Admin{}).Where("id = ?", adminID).
		Updates(map[string]any{"totp_enabled": true, "totp_secret": secret}).Error; err != nil {
		t.Fatalf("写入 TOTP 密钥失败: %v", err)
	}
	return secret
}

func TestStepUpDisabledByDefault(t *testing.T) {
	svc := newTestServices(t, nil)
	if svc.StepUpEnabled() {
		t.Fatal("step-up 默认应关闭，否则上线即打断所有管理员操作")
	}
}

func TestStepUpRequiresTOTPEnabled(t *testing.T) {
	svc := newTestServices(t, nil)
	a := mustAdmin(t, svc, "stepup_no_totp", "super")

	if _, err := svc.VerifyAdminStepUp(a.ID, "123456", "sess-1"); !errors.Is(err, ErrStepUpTOTPNotEnabled) {
		t.Fatalf("未启用 2FA 时应明确拒绝，实际 %v", err)
	}
	if _, err := svc.VerifyAdminStepUp(a.ID, "123456", ""); !errors.Is(err, ErrStepUpNoSession) {
		t.Fatalf("缺少会话标识时应拒绝，实际 %v", err)
	}
}

func TestStepUpGrantScopedToSession(t *testing.T) {
	svc := newTestServices(t, nil)
	a := mustAdmin(t, svc, "stepup_ok", "super")
	secret := enableAdminTOTP(t, svc, a.ID)

	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("生成动态口令失败: %v", err)
	}
	expires, err := svc.VerifyAdminStepUp(a.ID, code, "sess-a")
	if err != nil {
		t.Fatalf("正确口令应发放授权: %v", err)
	}
	if !expires.After(time.Now()) {
		t.Fatalf("授权到期时间应在未来")
	}
	if !svc.HasStepUpGrant(a.ID, "sess-a") {
		t.Fatal("刚发放的授权应生效")
	}
	if svc.HasStepUpGrant(a.ID, "sess-b") {
		t.Fatal("授权必须按会话隔离，不能跨登录令牌复用")
	}
	if svc.HasStepUpGrant(a.ID+1, "sess-a") {
		t.Fatal("授权必须按管理员隔离")
	}

	if _, err := svc.VerifyAdminStepUp(a.ID, code, "sess-b"); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("同一时间步的口令不能重复使用，实际 %v", err)
	}
}

func TestStepUpGrantExpires(t *testing.T) {
	svc := newTestServices(t, nil)
	a := mustAdmin(t, svc, "stepup_expire", "super")
	secret := enableAdminTOTP(t, svc, a.ID)

	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("生成动态口令失败: %v", err)
	}
	if _, err := svc.VerifyAdminStepUp(a.ID, code, "sess-x"); err != nil {
		t.Fatalf("发放授权失败: %v", err)
	}
	if err := svc.DB.Model(&model.StepUpGrant{}).Where("admin_id = ?", a.ID).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatalf("回填过期时间失败: %v", err)
	}
	if svc.HasStepUpGrant(a.ID, "sess-x") {
		t.Fatal("过期授权不该继续放行")
	}

	svc.PurgeExpiredStepUpGrants(time.Now())
	var n int64
	if err := svc.DB.Model(&model.StepUpGrant{}).Where("admin_id = ?", a.ID).Count(&n).Error; err != nil {
		t.Fatalf("统计授权失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("维护任务应清掉过期授权，实际还剩 %d 条", n)
	}
}

func TestStepUpDropGrant(t *testing.T) {
	svc := newTestServices(t, nil)
	a := mustAdmin(t, svc, "stepup_drop", "super")
	secret := enableAdminTOTP(t, svc, a.ID)

	code, err := auth.GenerateTOTP(secret, time.Now())
	if err != nil {
		t.Fatalf("生成动态口令失败: %v", err)
	}
	if _, err := svc.VerifyAdminStepUp(a.ID, code, "sess-drop"); err != nil {
		t.Fatalf("发放授权失败: %v", err)
	}
	svc.DropStepUpGrant(a.ID)
	if svc.HasStepUpGrant(a.ID, "sess-drop") {
		t.Fatal("吊销后授权必须立即失效（改密、重置 2FA 时调用）")
	}
}
