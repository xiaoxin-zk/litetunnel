package service

import (
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestProxyDrainIntentAbandonedWhenIncarnationChanged(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "incarndrain", Password: "not-used", Status: model.UserStatusDisabled}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if u.Incarnation == "" {
		t.Fatal("创建账号时必须自动生成生命周期标识")
	}

	row := model.ProxyDrainPending{
		UserID:      u.ID,
		Incarnation: u.Incarnation,
		Prefix:      FrpUserOf(u.ID) + ".",
		StatusGen:   u.StateVersion,
	}
	if intent, asDeleted := svc.proxyDrainIntentState(row); intent != proxyDrainIntentActive || asDeleted {
		t.Fatalf("标识一致时意图应有效，实际 intent=%v asDeleted=%v", intent, asDeleted)
	}

	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("incarnation", "another-lifecycle").Error; err != nil {
		t.Fatalf("改写账号标识失败: %v", err)
	}

	if intent, _ := svc.proxyDrainIntentState(row); intent != proxyDrainIntentAbandoned {
		t.Fatalf("账号标识变化后旧待办必须作废，实际 intent=%v", intent)
	}
}

func TestDeletedDrainIntentAbandonedWhenIDReused(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "reusedid", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	row := model.ProxyDrainPending{
		UserID:      u.ID,
		Incarnation: "the-deleted-lifecycle",
		Prefix:      FrpUserOf(u.ID) + ".",
		Deleted:     true,
	}
	if intent, asDeleted := svc.proxyDrainIntentState(row); intent != proxyDrainIntentAbandoned || asDeleted {
		t.Fatalf("ID 已被新账号占用时删号意图必须作废，实际 intent=%v asDeleted=%v", intent, asDeleted)
	}

	row.Incarnation = u.Incarnation
	if intent, asDeleted := svc.proxyDrainIntentState(row); intent != proxyDrainIntentAbandoned || asDeleted {
		t.Fatalf("标识相同但账号仍在时旧意图必须作废，实际 intent=%v asDeleted=%v", intent, asDeleted)
	}

	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatalf("删用户失败: %v", err)
	}
	if intent, asDeleted := svc.proxyDrainIntentState(row); intent != proxyDrainIntentActive || !asDeleted {
		t.Fatalf("账号不存在时应继续删号语义，实际 intent=%v asDeleted=%v", intent, asDeleted)
	}
}
