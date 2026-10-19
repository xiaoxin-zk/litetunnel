package service

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 删号后的即时断流与后台重试都读不到 users 行。若它们重新登记一次待办，
// 就会把删除事务里记下的账号标识覆盖成空串——ID 被复用时这条待办再也识别
// 不出「这是另一个账号」，会按相同前缀关掉新账号的代理。
//
// 这个用例走完整链路：删号事务登记 → 即时断流（frps 缺失，走 unknown 分支）
// → ID 被新账号占用 → 到期待办重试。断言旧待办既不覆盖标识，也不触碰新代理。
func TestDeletedDrainKeepsIncarnationAndSparesReusedID(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "reuse-drain")
	proxy := FrpUserOf(u.ID) + ".mc"

	var fence string
	if err := svc.DB.Transaction(func(tx *gorm.DB) error {
		fence = svc.recordProxyDrainPendingDB(tx, proxyDrainRequest{
			userID:  u.ID,
			prefix:  FrpUserOf(u.ID) + ".",
			deleted: true,
		})
		if fence == "" {
			t.Fatal("删除事务内应登记断流待办")
		}
		return tx.Delete(&model.User{}, u.ID).Error
	}); err != nil {
		t.Fatalf("删除事务失败: %v", err)
	}

	var row model.ProxyDrainPending
	if err := svc.DB.First(&row, u.ID).Error; err != nil {
		t.Fatalf("读回待办失败: %v", err)
	}
	oldInc := row.Incarnation
	if oldInc == "" {
		t.Fatal("删除事务内的待办必须记录账号标识")
	}

	// 即时断流：frps 不可用 → unknown，且**不能**重写待办。
	svc.Frps = nil
	svc.CloseDeletedUserProxies(context.Background(), u.ID)

	if err := svc.DB.First(&row, u.ID).Error; err != nil {
		t.Fatalf("即时断流后待办不应消失: %v", err)
	}
	if row.Incarnation != oldInc {
		t.Fatalf("即时断流覆盖了账号标识：%q → %q", oldInc, row.Incarnation)
	}

	// ID 被新账号占用，并注册了同名代理（新实例身份）。
	reused := &model.User{ID: u.ID, Username: "reuse-drain-new", Password: "not-used",
		Status: model.UserStatusActive}
	if err := svc.DB.Create(reused).Error; err != nil {
		t.Fatalf("新账号占用同一 ID 失败: %v", err)
	}
	if reused.Incarnation == oldInc {
		t.Fatal("新账号必须拿到不同的账号标识")
	}

	f := newFakeFrpsProxies(t, proxyJSON(proxy, "client-new", time.Now().Unix()))
	f.install(svc)

	// 让待办到期，跑一轮后台重试。
	if err := svc.DB.Model(&model.ProxyDrainPending{}).Where("user_id = ?", u.ID).
		Update("next_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("调整待办时间失败: %v", err)
	}
	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("旧删号待办不得关闭新账号的代理，实际关闭了 %v", got)
	}
	var left int64
	if err := svc.DB.Model(&model.ProxyDrainPending{}).Where("user_id = ?", u.ID).
		Count(&left).Error; err != nil {
		t.Fatalf("统计待办失败: %v", err)
	}
	if left != 0 {
		t.Fatalf("作废的待办应被清除，仍剩 %d 条", left)
	}
}
