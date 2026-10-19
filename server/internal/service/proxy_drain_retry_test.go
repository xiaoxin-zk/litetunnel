package service

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func loadDrainPending(t *testing.T, svc *Services, userID uint) (model.ProxyDrainPending, bool) {
	t.Helper()
	var rows []model.ProxyDrainPending
	if err := svc.DB.Where("user_id = ?", userID).Limit(1).Find(&rows).Error; err != nil {
		t.Fatalf("读取断流待办失败: %v", err)
	}
	if len(rows) == 0 {
		return model.ProxyDrainPending{}, false
	}
	return rows[0], true
}

func makeDrainDue(t *testing.T, svc *Services, userID uint) {
	t.Helper()
	if err := svc.DB.Model(&model.ProxyDrainPending{}).Where("user_id = ?", userID).
		Update("next_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("把待办拨到到期失败: %v", err)
	}
}

func TestCloseUserProxiesPersistsPendingWhenFrpsUnavailable(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainpersist")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past))
	f.setFailAll(true)
	f.install(svc)

	before := time.Now().Add(-time.Second)
	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败（frps 不可用不该影响账号状态）: %v", err)
	}

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("frps 不可用时不该发出关闭请求，实际 %v", got)
	}

	row, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("断流失败后必须留下待办：否则重启后没有任何补偿机会，代理会一直跑着")
	}
	if row.Deleted {
		t.Error("这是禁用路径，待办不能标成删号语义")
	}
	if row.Prefix != FrpUserOf(u.ID)+"." {
		t.Errorf("待办前缀 = %q，期望 %q", row.Prefix, FrpUserOf(u.ID)+".")
	}
	if row.StatusGen == 0 {
		t.Error("待办必须带上状态代次：重试时要靠它判断意图是否已被重新启用作废")
	}
	if row.NotAfter == 0 || row.NotAfter < before.Unix() {
		t.Errorf("待办必须记住禁用生效时刻（not_after=%d），重试才能跳过禁用后新注册的代理", row.NotAfter)
	}
	if row.Exhausted {
		t.Error("首次失败不该直接进终态")
	}
	if row.Attempts == 0 {
		t.Error("失败一次后应记下重试次数")
	}
}

func TestProxyDrainWorkerClosesResidualAfterFrpsRecovers(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainrecover")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t,
		proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past),
		proxyJSON(FrpUserOf(u.ID)+".nas", "client-b", past),
	)
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if _, ok := loadDrainPending(t, svc, u.ID); !ok {
		t.Fatal("前置条件：断流失败应留下待办")
	}

	f.setFailAll(false)
	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())

	got := f.closedNames()
	want := map[string]bool{
		FrpUserOf(u.ID) + ".mc":  true,
		FrpUserOf(u.ID) + ".nas": true,
	}
	if len(got) != len(want) {
		t.Fatalf("frps 恢复后应补关 2 条代理，实际 %v", got)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("关闭了不该关的代理 %q", name)
		}
	}
	if _, ok := loadDrainPending(t, svc, u.ID); ok {
		t.Fatal("关干净之后待办必须删除，否则每轮重试都空转")
	}
}

func TestProxyDrainRetryAbandonsWhenAccountReEnabled(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainreenable")

	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", time.Now().Add(-time.Minute).Unix()))
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if _, ok := loadDrainPending(t, svc, u.ID); !ok {
		t.Fatal("前置条件：断流失败应留下待办")
	}

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	f.setFailAll(false)
	f.setItems(proxyJSON(FrpUserOf(u.ID)+".mc", "client-b", time.Now().Unix()))

	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("账号已被重新启用，重试不得关闭任何代理，实际关闭了 %v", got)
	}
	if _, ok := loadDrainPending(t, svc, u.ID); ok {
		t.Fatal("意图已作废的待办必须删除，否则每轮都会把这条过期意图再判一次")
	}
}

func TestProxyDrainRetryUsesDeleteSemanticsWhenAccountRemoved(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "draindeleted")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past))
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("frps 不可用时删除仍必须成功: %v", err)
	}
	row, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("删除路径也必须留下待办")
	}
	if !row.Deleted {
		t.Fatal("删号意图必须覆盖禁用意图：账号都没了，关干净就对了")
	}

	f.setFailAll(false)
	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 1 || got[0] != FrpUserOf(u.ID)+".mc" {
		t.Fatalf("账号已删除时重试仍应按前缀关闭其代理，实际 %v", got)
	}
	if _, ok := loadDrainPending(t, svc, u.ID); ok {
		t.Fatal("关干净之后待办必须删除")
	}
}

func TestProxyDrainRetrySkipsReRegisteredInstance(t *testing.T) {
	svc := newTestServices(t, nil)
	const userID = 808
	name := FrpUserOf(userID) + ".mc"

	old := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t, proxyJSON(name, "client-new", time.Now().Unix()))
	f.install(svc)

	rec := model.ProxyDrainPending{
		UserID:   userID,
		Prefix:   FrpUserOf(userID) + ".",
		Deleted:  true,
		IntentAt: old,
		Targets:  proxyDrainTargetsJSON([]proxyDrainTarget{{Name: name, ClientID: "client-old", LastStartAt: old}}),
		NextAt:   time.Now().Add(-time.Minute),
		Fence:    "fence-test",
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("造待办失败: %v", err)
	}

	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("同名代理已经是新实例，重试不得按名字关闭，实际关闭了 %v", got)
	}
	if _, ok := loadDrainPending(t, svc, userID); ok {
		t.Fatal("没有需要关闭的旧实例时，待办应清掉（否则每轮都会空转）")
	}
}

func TestProxyDrainRetrySkipsProxiesStartedAfterIntent(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainwatermark")

	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".old", "client-a", time.Now().Add(-time.Minute).Unix()))
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	row, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("前置条件：断流失败应留下待办")
	}

	f.setFailAll(false)
	f.setItems(
		proxyJSON(FrpUserOf(u.ID)+".old", "client-a", time.Now().Add(-time.Minute).Unix()),
		proxyJSON(FrpUserOf(u.ID)+".new", "client-a", row.NotAfter+60),
	)

	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 1 || got[0] != FrpUserOf(u.ID)+".old" {
		t.Fatalf("只应关闭禁用前就存在的代理，实际关闭了 %v", got)
	}
}

func TestProxyDrainSingleBatchListForManyProxies(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainbatch")

	past := time.Now().Add(-time.Minute).Unix()
	items := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		items = append(items, proxyJSON(FrpUserOf(u.ID)+".t"+strconv.Itoa(i), "client-a", past))
	}
	f := newFakeFrpsProxies(t, items...)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}

	if got := f.closedNames(); len(got) != len(items) {
		t.Fatalf("6 条代理都应被关闭（都带实例身份、都早于禁用时刻），实际 %d 条: %v", len(got), got)
	}
	const maxLists = 3
	if n := f.listCount(); n > maxLists {
		t.Fatalf("一轮断流最多拉 %d 次批量列表（发现 1 + 复查 1 + 跨窗口余量 1），实际 %d 次；"+
			"若随代理条数增长就是缺陷 5 复发", maxLists, n)
	}
}

func TestProxyDrainBackoffGrowsAndCaps(t *testing.T) {
	if got := proxyDrainRetryDelay(0); got != proxyDrainBaseDelay {
		t.Fatalf("第 0 次（按第 1 次算）退避 = %s，期望 %s", got, proxyDrainBaseDelay)
	}
	if got := proxyDrainRetryDelay(1); got != proxyDrainBaseDelay {
		t.Fatalf("首次失败退避 = %s，期望 %s", got, proxyDrainBaseDelay)
	}
	prev := proxyDrainRetryDelay(1)
	for n := 2; n <= proxyDrainMaxAttempts; n++ {
		cur := proxyDrainRetryDelay(n)
		if cur < prev {
			t.Fatalf("退避必须单调不减：第 %d 次 %s < 第 %d 次 %s", n, cur, n-1, prev)
		}
		if cur > proxyDrainMaxDelay {
			t.Fatalf("退避不得越过上限：第 %d 次 %s > %s", n, cur, proxyDrainMaxDelay)
		}
		prev = cur
	}
	if got := proxyDrainRetryDelay(proxyDrainMaxAttempts); got != proxyDrainMaxDelay {
		t.Fatalf("到上限次数时退避应封顶为 %s，实际 %s", proxyDrainMaxDelay, got)
	}
}

func TestProxyDrainRetrySchedulesBackoffThenExhausts(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainbackoff")

	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", time.Now().Add(-time.Minute).Unix()))
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	first, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("前置条件：断流失败应留下待办")
	}
	if first.Attempts != 1 {
		t.Fatalf("首次失败后 attempts = %d，期望 1", first.Attempts)
	}
	if d := time.Until(first.NextAt); d < 20*time.Second {
		t.Fatalf("首次失败后应至少退避 30 秒，实际只剩 %s", d)
	}

	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())
	second, _ := loadDrainPending(t, svc, u.ID)
	if second.Attempts != 2 {
		t.Fatalf("第二次失败后 attempts = %d，期望 2", second.Attempts)
	}
	if d := time.Until(second.NextAt); d < 50*time.Second {
		t.Fatalf("第二次失败的退避应接近 60 秒，实际只剩 %s", d)
	}
	if second.NextAt.Before(first.NextAt) {
		t.Fatal("下一轮重试时间必须单调往后，不能倒退")
	}

	if err := svc.DB.Model(&model.ProxyDrainPending{}).Where("user_id = ?", u.ID).
		Update("attempts", proxyDrainMaxAttempts-1).Error; err != nil {
		t.Fatalf("改 attempts 失败: %v", err)
	}
	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())

	final, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("到上限后必须**保留**待办记录，否则这条残留代理就再没有线索了")
	}
	if !final.Exhausted {
		t.Fatalf("连续失败 %d 次后应进终态，实际 attempts=%d exhausted=false",
			proxyDrainMaxAttempts, final.Attempts)
	}
	if n, err := svc.ProxyDrainPendingCount(); err != nil {
		t.Fatalf("统计待办数量失败: %v", err)
	} else if n != 0 {
		t.Fatalf("终态待办不该再计入「仍在重试」的数量，实际 %d", n)
	}

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("frps 一直不可用时不该有任何关闭请求，实际 %v", got)
	}
	makeDrainDue(t, svc, u.ID)
	svc.retryPendingProxyDrains(context.Background())
	again, _ := loadDrainPending(t, svc, u.ID)
	if again.Attempts != final.Attempts {
		t.Fatalf("终态待办不该再被重试，attempts 从 %d 变成了 %d", final.Attempts, again.Attempts)
	}
}

func TestProxyDrainPendingDeleteIntentWins(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "drainprecedence")

	disableFence := svc.recordProxyDrainPending(proxyDrainRequest{
		userID:   u.ID,
		prefix:   FrpUserOf(u.ID) + ".",
		gen:      3,
		notAfter: time.Now().Add(-time.Minute),
	})
	if disableFence == "" {
		t.Fatal("前置条件：禁用意图应登记成功")
	}

	deleteFence := svc.recordProxyDrainPending(proxyDrainRequest{
		userID:  u.ID,
		prefix:  FrpUserOf(u.ID) + ".",
		deleted: true,
	})
	if deleteFence == "" {
		t.Fatal("删号意图必须能覆盖禁用意图；否则已删除账号的残留代理再没有补偿机会")
	}
	if deleteFence == disableFence {
		t.Fatal("覆盖之后围栏令牌必须换成新的：旧令牌的回写不能改到新意图")
	}

	row, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("待办应仍存在")
	}
	if !row.Deleted {
		t.Fatal("删号意图应占住这一行，实际 deleted=false")
	}
	if row.Fence != deleteFence {
		t.Fatalf("待办持有的围栏令牌 = %q，期望删号意图的 %q", row.Fence, deleteFence)
	}

	stale := svc.recordProxyDrainPending(proxyDrainRequest{
		userID:   u.ID,
		prefix:   FrpUserOf(u.ID) + ".",
		gen:      2,
		notAfter: time.Now().Add(-time.Minute),
	})
	if stale != "" {
		t.Fatal("滞后的禁用意图不得覆盖删号意图，也不得被当成登记成功（否则会拿错令牌去删别人的待办）")
	}
	row, _ = loadDrainPending(t, svc, u.ID)
	if !row.Deleted {
		t.Fatal("删号意图应仍然是占住的那一个")
	}

	svc.clearProxyDrainPending(u.ID, disableFence)
	if _, ok := loadDrainPending(t, svc, u.ID); !ok {
		t.Fatal("旧令牌不该能删掉新意图的待办：那条待办还得继续跑")
	}
	svc.clearProxyDrainPending(u.ID, deleteFence)
	if _, ok := loadDrainPending(t, svc, u.ID); ok {
		t.Fatal("持有者用当前令牌应能清掉自己的待办")
	}
}

func TestProxyDrainRequestFromPendingUsesIntentAt(t *testing.T) {
	created := time.Now().Add(-time.Hour)
	intentAt := time.Now().Add(-time.Minute)

	req := requestFromPending(model.ProxyDrainPending{
		UserID:    900,
		Deleted:   true,
		IntentAt:  intentAt.Unix(),
		CreatedAt: created,
	})
	if !req.notAfter.Equal(time.Unix(intentAt.Unix(), 0)) {
		t.Fatalf("删除路径的水位应取 IntentAt（%s），实际 %s；取 CreatedAt 会让水位往前漂、偏向误杀",
			intentAt.Format(time.RFC3339), req.notAfter.Format(time.RFC3339))
	}

	legacy := requestFromPending(model.ProxyDrainPending{
		UserID:    901,
		Deleted:   true,
		CreatedAt: created,
	})
	if !legacy.notAfter.Equal(created) {
		t.Fatalf("老记录的删除路径水位应退回 CreatedAt（%s），实际 %s",
			created.Format(time.RFC3339), legacy.notAfter.Format(time.RFC3339))
	}

	disabled := requestFromPending(model.ProxyDrainPending{
		UserID:    902,
		StatusGen: 5,
		NotAfter:  created.Add(time.Minute).Unix(),
		IntentAt:  intentAt.Unix(),
	})
	if !disabled.notAfter.Equal(time.Unix(created.Add(time.Minute).Unix(), 0)) {
		t.Fatalf("禁用路径的水位应取 NotAfter，实际 %s", disabled.notAfter.Format(time.RFC3339))
	}
	if disabled.deleted {
		t.Fatal("禁用路径不该被重建为删号语义")
	}
	if disabled.gen != 5 {
		t.Fatalf("重建请求必须带上状态代次，实际 %d", disabled.gen)
	}
}
