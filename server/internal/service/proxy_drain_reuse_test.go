package service

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestPurgeIntentsSetsFence(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "purge-fence")

	var fence string
	if err := svc.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := recordPurgeIntentsTx(tx, u.ID, u.Incarnation, nil); err != nil {
			return err
		}
		var row model.ProxyDrainPending
		if err := tx.First(&row, u.ID).Error; err != nil {
			return err
		}
		fence = row.Fence
		if row.Incarnation != u.Incarnation {
			t.Errorf("删号待办应记录事务内的账号标识，实际 %q", row.Incarnation)
		}
		return nil
	}); err != nil {
		t.Fatalf("登记删号意图失败: %v", err)
	}
	if fence == "" {
		t.Fatal("删号事务必须生成围栏令牌，否则即时断流会重写待办")
	}

	svc.Frps = nil
	svc.CloseDeletedUserProxies(context.Background(), u.ID)

	var after model.ProxyDrainPending
	if err := svc.DB.First(&after, u.ID).Error; err != nil {
		t.Fatalf("即时断流后待办不应消失: %v", err)
	}
	if after.Fence != fence {
		t.Fatalf("即时断流重写了围栏令牌：%q → %q", fence, after.Fence)
	}
	if after.Incarnation != u.Incarnation {
		t.Fatalf("即时断流覆盖了账号标识：%q → %q", u.Incarnation, after.Incarnation)
	}
}

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

	svc.Frps = nil
	svc.CloseDeletedUserProxies(context.Background(), u.ID)

	if err := svc.DB.First(&row, u.ID).Error; err != nil {
		t.Fatalf("即时断流后待办不应消失: %v", err)
	}
	if row.Incarnation != oldInc {
		t.Fatalf("即时断流覆盖了账号标识：%q → %q", oldInc, row.Incarnation)
	}

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
