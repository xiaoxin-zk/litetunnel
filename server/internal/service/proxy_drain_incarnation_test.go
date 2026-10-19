package service

import (
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 断流待办必须能识别「同一个自增 ID 已经是另一个账号」。
//
// 导入、恢复或手工重建账号都可能复用旧 ID。若只按 user_id 判断，旧删除/
// 禁用意图会被当成当前账号的，按相同前缀把新账号刚建立的代理全部关掉。
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

	// 模拟 ID 复用：同一行用户被换成了另一个生命周期。
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("incarnation", "another-lifecycle").Error; err != nil {
		t.Fatalf("改写账号标识失败: %v", err)
	}

	if intent, _ := svc.proxyDrainIntentState(row); intent != proxyDrainIntentAbandoned {
		t.Fatalf("账号标识变化后旧待办必须作废，实际 intent=%v", intent)
	}
}

// 删号意图同样不能跨生命周期生效：账号已删除，但 ID 被新账号占用时，
// 按相同前缀关闭代理会误伤新账号。
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

	// 确认账号确实不存在时仍按删号语义继续（不能因为校验而放弃断流）。
	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatalf("删用户失败: %v", err)
	}
	if intent, asDeleted := svc.proxyDrainIntentState(row); intent != proxyDrainIntentActive || !asDeleted {
		t.Fatalf("账号不存在时应继续删号语义，实际 intent=%v asDeleted=%v", intent, asDeleted)
	}
}
