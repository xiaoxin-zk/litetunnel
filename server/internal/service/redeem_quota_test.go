package service

import (
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func redeemTrafficQuotaBase(t *testing.T, expireAt *time.Time) (*Services, *model.User, string) {
	t.Helper()
	svc := newTestServices(t, nil)

	vip := &model.Group{Name: "vip", AllowProtocols: "tcp", TrafficQuota: 100 << 30}
	if err := svc.DB.Create(vip).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	def := &model.Group{Name: "default", AllowProtocols: "tcp", IsDefault: true, TrafficQuota: 10 << 30}
	if err := svc.DB.Create(def).Error; err != nil {
		t.Fatalf("建默认分组失败: %v", err)
	}

	u := &model.User{
		Username: "quotaredeem", Password: "not-used", Status: model.UserStatusActive,
		GroupID: vip.ID, GroupExpireAt: expireAt,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	code := &model.RedeemCode{
		Code: "TRAFQUOTA1", BatchNo: "B1", Type: model.RedeemTypeTraffic,
		Value: 1 << 30, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建兑换码失败: %v", err)
	}
	return svc, u, code.Code
}

func TestRedeemTrafficUsesEffectiveGroupQuota(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	svc, u, code := redeemTrafficQuotaBase(t, &past)

	if _, err := svc.Redeem(u.ID, code, "127.0.0.1"); err != nil {
		t.Fatalf("兑换失败: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatalf("读用户失败: %v", err)
	}
	if want := int64(11 << 30); got.TrafficQuota != want {
		t.Fatalf("过期分组应按默认分组配额叠加：期望 %d，实际 %d", want, got.TrafficQuota)
	}
}

func TestRedeemTrafficUsesActiveGroupQuota(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	svc, u, code := redeemTrafficQuotaBase(t, &future)

	if _, err := svc.Redeem(u.ID, code, "127.0.0.1"); err != nil {
		t.Fatalf("兑换失败: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatalf("读用户失败: %v", err)
	}
	if want := int64(101 << 30); got.TrafficQuota != want {
		t.Fatalf("未过期时应按自身分组配额叠加：期望 %d，实际 %d", want, got.TrafficQuota)
	}
}
