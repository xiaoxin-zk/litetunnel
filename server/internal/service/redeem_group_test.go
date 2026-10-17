package service

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

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

// TestGenerateCodesValueCapRejected 覆盖生成侧的面值上限。
func TestGenerateCodesValueCapRejected(t *testing.T) {
	svc := newTestServices(t, nil)

	_, err := svc.GenerateCodes(1, GenerateCodesInput{
		Count: 1, Type: model.RedeemTypeTraffic, Value: maxRedeemTrafficValue + 1,
	})
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超上限的流量值应被拒绝，实际 %v", err)
	}
	_, err = svc.GenerateCodes(1, GenerateCodesInput{
		Count: 1, Type: model.RedeemTypeDuration, Value: maxRedeemDurationValue + 1,
	})
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("超上限的天数应被拒绝，实际 %v", err)
	}
	_, err = svc.GenerateCodes(1, GenerateCodesInput{
		Count: 1, Type: model.RedeemTypeGroup, GroupID: 99999,
	})
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("指向不存在分组的码应被拒绝，实际 %v", err)
	}
}

// TestRedeemOverflowRejected 覆盖兑换侧的溢出兜底。
//
// 生成侧的面值上限管不住已存在的老数据：直接往库里塞一张超上限的码
// （绕过 GenerateCodes 的校验，模拟历史数据），兑换必须拒绝，
// 且码不能被核销——事务回滚后它还得能正常兑换。
func TestRedeemOverflowRejected(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "rich", Password: "not-used", Status: model.UserStatusActive,
		TrafficQuota: math.MaxInt64 - 10}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	code := &model.RedeemCode{
		Code: "OVERFLOW1", BatchNo: "B1", Type: model.RedeemTypeTraffic,
		Value: 100, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建码失败: %v", err)
	}

	_, err := svc.Redeem(u.ID, code.Code, "127.0.0.1")
	if !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("溢出兑换应被拒绝，实际 %v", err)
	}

	// 拒绝后码必须原样保留：核销随事务回滚。
	var after model.RedeemCode
	if err := svc.DB.First(&after, code.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.RedeemStatusUnused || after.UsedCount != 0 {
		t.Fatalf("被拒绝的码不应被核销: status=%s used=%d", after.Status, after.UsedCount)
	}
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.TrafficQuota != math.MaxInt64-10 {
		t.Fatalf("配额不应被改写，实际 %d", got.TrafficQuota)
	}
}

// TestRedeemDurationStacksSequentially 覆盖时长码的顺延。
//
// 顺延基于「现有到期时间」：第二张必须从第一张的结果继续叠加，
// 而不是各自从当前时间起算。行锁保证并发兑换时读到的也是前一张
// 提交后的值（并发本身无法在 SQLite 单连接下复现，这里守住语义）。
func TestRedeemDurationStacksSequentially(t *testing.T) {
	svc := newTestServices(t, nil)

	base := time.Now().AddDate(0, 0, 10)
	u := &model.User{Username: "dur", Password: "not-used", Status: model.UserStatusActive,
		GroupExpireAt: &base}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	for i := 0; i < 2; i++ {
		code := &model.RedeemCode{
			Code: "DURATION1" + string(rune('A'+i)), BatchNo: "B1",
			Type: model.RedeemTypeDuration, Value: 30,
			MaxUses: 1, Status: model.RedeemStatusUnused,
		}
		if err := svc.DB.Create(code).Error; err != nil {
			t.Fatalf("建码失败: %v", err)
		}
		if _, err := svc.Redeem(u.ID, code.Code, "127.0.0.1"); err != nil {
			t.Fatalf("第 %d 次兑换失败: %v", i+1, err)
		}
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	// 10 天 + 30 + 30，允许几秒的时钟误差。
	want := base.AddDate(0, 0, 60)
	if diff := got.GroupExpireAt.Sub(want); diff > 2*time.Minute || diff < -2*time.Minute {
		t.Fatalf("到期时间应顺延到 %v，实际 %v", want, *got.GroupExpireAt)
	}
}

// TestAdminSetUserGroupWithMissingGroupFails 覆盖「分配时分组已不存在」。
func TestAdminSetUserGroupWithMissingGroupFails(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "gone", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u := &model.User{Username: "assignme", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DeleteGroup(g.ID); err != nil {
		t.Fatalf("删除分组失败: %v", err)
	}

	err := svc.AdminSetUserGroup(u.ID, g.ID, nil)
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("向已删除分组分配用户应被拒绝，实际 %v", err)
	}
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupID == g.ID {
		t.Fatal("悬空的 group_id 不应被写入")
	}
}
