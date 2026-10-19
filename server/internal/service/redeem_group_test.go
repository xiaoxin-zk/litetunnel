package service

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestGroupCodeRefusedWhenMembershipExpired(t *testing.T) {
	svc := newTestServices(t, nil)

	oldGroup := &model.Group{Name: "rg-old", AllowProtocols: "tcp"}
	newGroup := &model.Group{Name: "rg-new", AllowProtocols: "tcp"}
	for _, g := range []*model.Group{oldGroup, newGroup} {
		if err := svc.DB.Create(g).Error; err != nil {
			t.Fatalf("建分组失败: %v", err)
		}
	}
	past := time.Now().Add(-time.Hour)
	u := &model.User{
		Username: "expiredredeem", Password: "not-used", Status: model.UserStatusActive,
		GroupID: oldGroup.ID, GroupExpireAt: &past,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	code := &model.RedeemCode{
		Code: "GRPEXPIRED1", BatchNo: "B1", Type: model.RedeemTypeGroup,
		GroupID: newGroup.ID, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建码失败: %v", err)
	}

	_, err := svc.Redeem(u.ID, code.Code, "127.0.0.1")
	if err == nil {
		t.Fatal("分组有效期已过时兑换分组码应被拒绝（否则码被核销、用户仍被回落默认组）")
	}
	if !errors.Is(err, ErrMembershipExpired) {
		t.Fatalf("应返回 ErrMembershipExpired（映射为 400），实际: %v", err)
	}
	if !strings.Contains(err.Error(), "过期") {
		t.Fatalf("错误信息应说明有效期已过，实际: %v", err)
	}

	var after model.RedeemCode
	if err := svc.DB.First(&after, code.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.UsedCount != 0 || after.Status != model.RedeemStatusUnused {
		t.Fatalf("被拒绝的兑换不得核销码：used=%d status=%s", after.UsedCount, after.Status)
	}
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupID != oldGroup.ID {
		t.Fatal("被拒绝时不应改动分组")
	}
}

func TestDurationThenGroupCodeApplies(t *testing.T) {
	svc := newTestServices(t, nil)

	oldGroup := &model.Group{Name: "rg2-old", AllowProtocols: "tcp"}
	newGroup := &model.Group{Name: "rg2-new", AllowProtocols: "tcp"}
	for _, g := range []*model.Group{oldGroup, newGroup} {
		if err := svc.DB.Create(g).Error; err != nil {
			t.Fatalf("建分组失败: %v", err)
		}
	}
	past := time.Now().Add(-time.Hour)
	u := &model.User{
		Username: "renewfirst", Password: "not-used", Status: model.UserStatusActive,
		GroupID: oldGroup.ID, GroupExpireAt: &past,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	dur := &model.RedeemCode{
		Code: "DUR30FIRST", BatchNo: "B1", Type: model.RedeemTypeDuration,
		Value: 30, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	grp := &model.RedeemCode{
		Code: "GRPAFTERDUR", BatchNo: "B1", Type: model.RedeemTypeGroup,
		GroupID: newGroup.ID, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	for _, c := range []*model.RedeemCode{dur, grp} {
		if err := svc.DB.Create(c).Error; err != nil {
			t.Fatalf("建码失败: %v", err)
		}
	}

	if _, err := svc.Redeem(u.ID, dur.Code, "127.0.0.1"); err != nil {
		t.Fatalf("兑换时长码失败: %v", err)
	}
	svc.refreshGuardDue()

	if _, err := svc.Redeem(u.ID, grp.Code, "127.0.0.1"); err != nil {
		t.Fatalf("续期后兑换分组码应成功: %v", err)
	}
	svc.refreshGuardDue()

	var got model.User
	if err := svc.DB.Preload("Group").First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupID != newGroup.ID {
		t.Fatalf("分组码应已生效，实际 group_id=%d", got.GroupID)
	}
	if got.GroupExpireAt == nil || !got.GroupExpireAt.After(time.Now()) {
		t.Fatalf("有效期应保持在未来，实际 %v", got.GroupExpireAt)
	}
	if g := svc.EffectiveGroup(&got); g == nil || g.ID != newGroup.ID {
		t.Fatal("生效分组必须是新分组（不能被回落成默认组）")
	}
}

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
	var cnt int64
	if err := svc.DB.Model(&model.Group{}).Where("id = ?", g.ID).Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatal("分组不应被删除")
	}

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
	if !strings.HasPrefix(first[0].BatchNo, "B") || len(first[0].BatchNo) < 15 {
		t.Fatalf("批次号格式异常: %s", first[0].BatchNo)
	}
}

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
	want := base.AddDate(0, 0, 60)
	if diff := got.GroupExpireAt.Sub(want); diff > 2*time.Minute || diff < -2*time.Minute {
		t.Fatalf("到期时间应顺延到 %v，实际 %v", want, *got.GroupExpireAt)
	}
}

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

	err := svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{})
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
