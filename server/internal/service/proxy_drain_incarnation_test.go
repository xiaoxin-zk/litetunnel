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
