package service

import (
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守两件事：
//
//  1. 删除分组不得留下「无法兑换」的升级码——GenerateCodes 允许生成指向
//     现存分组的码，分组一删这些码就在兑换时报「无效」，用户拿着永远
//     用不掉的码。必须在删除前拦下。
//  2. 批次号在同一秒内两次生成不得撞号——管理页按批次号筛选，
//     撞号的两批码在批次维度就失去了意义。

func TestDeleteGroupRefusedWhileUnusedGroupCodesExist(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "vip", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	code := &model.RedeemCode{
		Code: "TESTCODE1", BatchNo: "B1", Type: model.RedeemTypeGroup,
		GroupID: g.ID, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建兑换码失败: %v", err)
	}

	err := svc.DeleteGroup(g.ID)
	if err == nil {
		t.Fatal("仍有未核销的分组升级码时，删除分组应被拒绝")
	}
	if !strings.Contains(err.Error(), "升级码") {
		t.Fatalf("错误信息应指出升级码问题，实际: %v", err)
	}
	// 分组必须还在：拒绝删除不是走个过场。
	var cnt int64
	if err := svc.DB.Model(&model.Group{}).Where("id = ?", g.ID).Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatal("分组不应被删除")
	}

	// 码用尽之后（状态变 used_up）就可以删了：
	// 已用尽的码不能再兑换，指向已删除分组对它没有影响。
	code.Status = model.RedeemStatusUsedUp
	if err := svc.DB.Save(code).Error; err != nil {
		t.Fatalf("核销码失败: %v", err)
	}
	if err := svc.DeleteGroup(g.ID); err != nil {
		t.Fatalf("核销后应允许删除分组: %v", err)
	}
}

func TestDeleteGroupRefusedWhileGroupHasUsers(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "vip2", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u := &model.User{Username: "vipuser", Password: "not-used", Status: model.UserStatusActive, GroupID: g.ID}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.DeleteGroup(g.ID); err == nil {
		t.Fatal("仍有用户属于该分组时，删除应被拒绝")
	}
}

// TestGenerateCodesBatchNoUniqueWithinSameSecond 覆盖批次号撞号。
//
// 原实现只用秒级时间戳：同一秒点两次「生成」，两批码共用一个批次号，
// 管理页按批次筛选时混在一起。这里在无 sleep 的连续调用下断言两批不同。
func TestGenerateCodesBatchNoUniqueWithinSameSecond(t *testing.T) {
	svc := newTestServices(t, nil)

	first, err := svc.GenerateCodes(1, GenerateCodesInput{
		Count: 1, Type: model.RedeemTypeTraffic, Value: 1024, MaxUses: 1,
	})
	if err != nil {
		t.Fatalf("第一批生成失败: %v", err)
	}
	second, err := svc.GenerateCodes(1, GenerateCodesInput{
		Count: 1, Type: model.RedeemTypeTraffic, Value: 1024, MaxUses: 1,
	})
	if err != nil {
		t.Fatalf("第二批生成失败: %v", err)
	}

	if first[0].BatchNo == second[0].BatchNo {
		t.Fatalf("同一秒内两批的批次号不应相同，实际均为 %s", first[0].BatchNo)
	}
	// 批次号仍应以 B + 时间开头：按时间前缀筛选的用法不能被破坏。
	if !strings.HasPrefix(first[0].BatchNo, "B") || len(first[0].BatchNo) < 15 {
		t.Fatalf("批次号格式异常: %s", first[0].BatchNo)
	}
}
