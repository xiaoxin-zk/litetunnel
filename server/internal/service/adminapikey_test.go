package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestAdminAPIKeyLifecycle(t *testing.T) {
	svc := newTestServices(t, nil)
	admin := mustAdmin(t, svc, "keymaker", "super")

	plain, view, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{Name: "监控探针"})
	if err != nil {
		t.Fatalf("创建 Key 失败: %v", err)
	}
	if !strings.HasPrefix(plain, AdminAPIKeyPrefix) {
		t.Fatalf("Key 前缀应能与管理端令牌区分，实际 %q", plain)
	}
	if view.Scope != AdminKeyScopeRead {
		t.Fatalf("管理员 Key 只应为只读作用域，实际 %q", view.Scope)
	}
	if view.Masked == "" || strings.Contains(view.Masked, plain[8:16]) {
		t.Fatalf("列表展示应掩码前缀之上的内容，实际 %q", view.Masked)
	}

	var plainStored int64
	if err := svc.DB.Model(&model.AdminAPIKey{}).Where("key_hash = ?", plain).Count(&plainStored).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if plainStored != 0 {
		t.Fatal("明文绝不能落库，只能存哈希")
	}

	id, name, scope, ok := svc.ResolveAdminAPIKey(plain)
	if !ok {
		t.Fatal("刚创建的 Key 应能通过校验")
	}
	if id != admin.ID || name != "监控探针" || scope != AdminKeyScopeRead {
		t.Fatalf("解析出的身份不正确: %d %q %q", id, name, scope)
	}

	if _, _, _, ok := svc.ResolveAdminAPIKey("ltadm_deadbeef"); ok {
		t.Fatal("不存在的 Key 不该通过校验")
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey("lt_abcd"); ok {
		t.Fatal("用户级 Key 前缀不该被管理员 Key 接受")
	}

	if err := svc.RevokeAdminAPIKey(view.ID); err != nil {
		t.Fatalf("吊销失败: %v", err)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); ok {
		t.Fatal("吊销后 Key 必须立即失效")
	}
	if err := svc.RevokeAdminAPIKey(view.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复吊销应返回资源不存在，实际 %v", err)
	}
}

func TestAdminAPIKeyDiesWithCreator(t *testing.T) {
	svc := newTestServices(t, nil)
	admin := mustAdmin(t, svc, "keyowner", "super")

	plain, _, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{Name: "监控"})
	if err != nil {
		t.Fatalf("创建 Key 失败: %v", err)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); !ok {
		t.Fatal("创建者正常时 Key 应可用")
	}

	if err := svc.DB.Model(&model.Admin{}).Where("id = ?", admin.ID).
		Update("status", "disabled").Error; err != nil {
		t.Fatalf("停用管理员失败: %v", err)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); ok {
		t.Fatal("创建者被停用后，遗留 Key 必须立刻失效")
	}

	if err := svc.DB.Delete(&model.Admin{}, admin.ID).Error; err != nil {
		t.Fatalf("删除管理员失败: %v", err)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); ok {
		t.Fatal("创建者被删除后，遗留 Key 必须立刻失效")
	}
}

func TestAdminAPIKeyExpiry(t *testing.T) {
	svc := newTestServices(t, nil)
	admin := mustAdmin(t, svc, "keyexpire", "super")

	plain, view, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{Name: "临时", ExpiresInDays: 7})
	if err != nil {
		t.Fatalf("创建 Key 失败: %v", err)
	}
	if view.ExpiresAt == nil || !view.ExpiresAt.After(time.Now()) {
		t.Fatal("设置了有效期时应落在未来")
	}

	if err := svc.DB.Model(&model.AdminAPIKey{}).Where("id = ?", view.ID).
		Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("回填过期时间失败: %v", err)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); ok {
		t.Fatal("过期 Key 不该通过校验")
	}
}

func TestAdminAPIKeyRejectsBadInput(t *testing.T) {
	svc := newTestServices(t, nil)
	admin := mustAdmin(t, svc, "keybad", "super")

	if _, _, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{ExpiresInDays: -1}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("负数有效期应被拒绝，实际 %v", err)
	}
	if _, _, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{ExpiresInDays: 3651}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超长有效期应被拒绝，实际 %v", err)
	}
	if _, _, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{Name: strings.Repeat("名", 65)}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超长名称应被拒绝，实际 %v", err)
	}

	plain, view, err := svc.CreateAdminAPIKey(admin.ID, AdminAPIKeyInput{})
	if err != nil {
		t.Fatalf("空名称应回落到默认名: %v", err)
	}
	if view.Name != "外部集成" {
		t.Fatalf("默认名称不正确，实际 %q", view.Name)
	}
	if _, _, _, ok := svc.ResolveAdminAPIKey(plain); !ok {
		t.Fatal("默认名称的 Key 应可用")
	}
}
