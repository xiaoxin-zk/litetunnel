package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestRefreshGuardForTrafficOnlyTouchesAffected(t *testing.T) {
	svc := newTestServices(t, nil)

	mkUser := func(name string, used int64) *model.User {
		u := &model.User{
			Username: name, Password: "not-used", Status: model.UserStatusActive,
			TrafficUsed: used, TrafficQuota: 100,
			TrafficResetAt: time.Now().AddDate(0, 1, 0),
		}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户 %s 失败: %v", name, err)
		}
		return u
	}
	active := mkUser("activeuser", 200)
	other := mkUser("otheruser", 200)

	svc.refreshGuardForTraffic(map[uint]int64{active.ID: 10})

	if !svc.Runtime.IsQuotaExceeded(active.ID) {
		t.Fatal("本轮有流量的超额用户必须被标成超额")
	}
	if svc.Runtime.IsQuotaExceeded(other.ID) {
		t.Fatal("没有流量的用户不该被本轮增量刷新写入；这里被写说明仍在扫全表")
	}
}

func TestRefreshGuardDueResetsPeriod(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "dueuser", Password: "not-used", Status: model.UserStatusActive,
		TrafficUsed: 500, TrafficQuota: 100,
		TrafficResetAt: time.Now().Add(-time.Hour),
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	svc.Runtime.markAccessGuardReady()
	svc.guardFullAt.Store(time.Now().UnixNano())

	svc.refreshGuardDue()

	var fresh model.User
	if err := svc.DB.First(&fresh, u.ID).Error; err != nil {
		t.Fatalf("重读用户失败: %v", err)
	}
	if fresh.TrafficUsed != 0 {
		t.Fatalf("到期用户的已用流量必须清零，实际 %d", fresh.TrafficUsed)
	}
	if !fresh.TrafficResetAt.After(time.Now()) {
		t.Fatalf("到期后应顺延到下一个周期，实际 %v", fresh.TrafficResetAt)
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("清零之后不应再是超额状态（否则该账号永远连不上）")
	}
}

func TestDueGuardUsersIncludesExpiredGroup(t *testing.T) {
	svc := newTestServices(t, nil)

	future := time.Now().AddDate(0, 1, 0)
	past := time.Now().Add(-time.Hour)

	mk := func(name string, expire *time.Time) *model.User {
		u := &model.User{
			Username: name, Password: "not-used", Status: model.UserStatusActive,
			TrafficResetAt: future,
			GroupExpireAt:  expire,
		}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户 %s 失败: %v", name, err)
		}
		return u
	}
	expired := mk("groupexpired", &past)
	fresh := mk("groupfresh", &future)
	never := mk("groupnever", nil)

	_, groupDue, err := svc.dueGuardUsers()
	if err != nil {
		t.Fatalf("查询到期用户失败: %v", err)
	}

	got := make(map[uint]bool, len(groupDue))
	for _, id := range groupDue {
		got[id] = true
	}
	if !got[expired.ID] {
		t.Fatal("分组已到期的用户必须被筛出来")
	}
	if got[fresh.ID] || got[never.ID] {
		t.Fatal("分组未到期的用户不该被筛出来（否则每轮又变成全量）")
	}
}

func TestRefreshGuardDueMigratesExpiredGroup(t *testing.T) {
	svc := newTestServices(t, nil)

	def := &model.Group{Name: "默认分组", IsDefault: true, TrafficQuota: 100}
	if err := svc.DB.Create(def).Error; err != nil {
		t.Fatalf("建默认分组失败: %v", err)
	}
	paid := &model.Group{Name: "付费分组", TrafficQuota: 100000}
	if err := svc.DB.Create(paid).Error; err != nil {
		t.Fatalf("建付费分组失败: %v", err)
	}

	past := time.Now().Add(-time.Hour)
	u := &model.User{
		Username: "expiredgroup", Password: "not-used", Status: model.UserStatusActive,
		GroupID:        paid.ID,
		GroupExpireAt:  &past,
		TrafficUsed:    500,
		TrafficResetAt: time.Now().AddDate(0, 1, 0),
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	svc.refreshGuardDue()

	var fresh model.User
	if err := svc.DB.First(&fresh, u.ID).Error; err != nil {
		t.Fatalf("重读用户失败: %v", err)
	}
	if fresh.GroupID != def.ID {
		t.Fatalf("到期用户应被落回默认分组，实际 group_id=%d（期望 %d）", fresh.GroupID, def.ID)
	}
	if fresh.GroupExpireAt != nil {
		t.Fatal("迁移后必须清掉到期时间，否则每轮都会被重新扫出来")
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("落回默认分组后应按默认组配额判定为超额")
	}

	_, groupDue, err := svc.dueGuardUsers()
	if err != nil {
		t.Fatalf("查询到期用户失败: %v", err)
	}
	for _, id := range groupDue {
		if id == u.ID {
			t.Fatal("迁移后的用户不该再被扫出来（否则每轮都在重算同一批历史过期用户）")
		}
	}
}

func TestMigrateExpiredGroupsInBatches(t *testing.T) {
	svc := newTestServices(t, nil)

	def := &model.Group{Name: "batch默认", IsDefault: true}
	paid := &model.Group{Name: "batch付费"}
	if err := svc.DB.Create(def).Error; err != nil {
		t.Fatalf("建默认分组失败: %v", err)
	}
	if err := svc.DB.Create(paid).Error; err != nil {
		t.Fatalf("建付费分组失败: %v", err)
	}

	past := time.Now().Add(-time.Hour)
	future := time.Now().AddDate(0, 1, 0)
	ids := make([]uint, 0, 5)
	for i := 0; i < 5; i++ {
		u := &model.User{
			Username: fmt.Sprintf("batchdue%d", i), Password: "not-used",
			Status: model.UserStatusActive, GroupID: paid.ID,
			GroupExpireAt: &past, TrafficResetAt: future,
		}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
		ids = append(ids, u.ID)
	}

	old := inQueryBatch
	inQueryBatch = 2
	t.Cleanup(func() { inQueryBatch = old })

	if err := svc.migrateExpiredGroups(ids); err != nil {
		t.Fatalf("分批迁移失败: %v", err)
	}

	var migrated int64
	if err := svc.DB.Model(&model.User{}).
		Where("group_id = ? AND group_expire_at IS NULL", def.ID).
		Count(&migrated).Error; err != nil {
		t.Fatal(err)
	}
	if migrated != int64(len(ids)) {
		t.Fatalf("应迁移 %d 名用户，实际 %d（批次边界漏了尾部）", len(ids), migrated)
	}
}

func TestGuardFullRefreshDue(t *testing.T) {
	svc := newTestServices(t, nil)

	if !svc.guardFullRefreshDue() {
		t.Fatal("首次调用应触发全量校准")
	}
	if svc.guardFullRefreshDue() {
		t.Fatal("刚校准过不该再次触发（否则等于每轮全表）")
	}

	svc.guardFullAt.Store(time.Now().Add(-quotaFullRefresh - time.Minute).UnixNano())
	if !svc.guardFullRefreshDue() {
		t.Fatal("超过校准间隔后应重新触发")
	}
}

func TestGuardVerBlocksStaleSnapshotWrite(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "guardver", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	stale := svc.Runtime.GuardVer()

	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)

	if ok := svc.Runtime.SetGuardFlagsIfVer(u.ID, false, false, stale); ok {
		t.Fatal("旧版本号的条件写应被拒绝")
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("管理员的超额标记被旧快照清掉了")
	}

	if ok := svc.Runtime.SetGuardFlagsIfVer(u.ID, false, false, svc.Runtime.GuardVer()); !ok {
		t.Fatal("当前版本号的条件写应成功")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("新快照应能正常刷新标记")
	}
}

func TestFlushTrafficKeepsMarkOnTxFailure(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	svc.Runtime.MarkTrafficResetPending(tun.UserID)

	if err := svc.DB.Migrator().DropTable(&model.TrafficDaily{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	err := svc.flushTraffic(
		map[uint]*tunnelDelta{tun.ID: {in: 100, out: 100}},
		map[uint]int64{tun.UserID: 500},
		map[uint]uint{tun.ID: tun.UserID},
		map[string]trafficPair{}, false, trafficFence{},
	)
	if err == nil {
		t.Fatal("日明细表缺失时落库应失败")
	}

	taken := svc.Runtime.takePendingTrafficResets()
	if len(taken) != 1 {
		t.Fatalf("事务失败后清零标记应保留在内存，实际 %v", taken)
	}

	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false, trafficFence{},
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 0 {
		t.Fatalf("保留的标记应继续抑制旧增量，实际用量 %d", got)
	}
	if left := svc.Runtime.takePendingTrafficResets(); len(left) != 0 {
		t.Fatalf("成功提交后标记应被消费摘除，实际 %v", left)
	}
	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 300},
		nil, map[string]trafficPair{}, false, trafficFence{},
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 300 {
		t.Fatalf("消费后的新增量应正常累加，实际 %d（期望 300）", got)
	}
}

func TestConsumePreservesRemarkedGeneration(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.MarkTrafficResetPending(1)
	taken := svc.Runtime.takePendingTrafficResets()

	svc.Runtime.MarkTrafficResetPending(1)

	svc.Runtime.consumePendingTrafficResets(taken)

	left := svc.Runtime.takePendingTrafficResets()
	if len(left) != 1 || !svc.Runtime.resetSkipValid(1, left[1]) {
		t.Fatalf("新登记的代次应保留且有效，实际 %v", left)
	}
}

func TestUnmarkInvalidatesTakenSnapshot(t *testing.T) {
	svc := newTestServices(t, nil)

	gen := svc.Runtime.MarkTrafficResetPending(7)
	taken := svc.Runtime.takePendingTrafficResets()
	if !svc.Runtime.resetSkipValid(7, taken[7]) {
		t.Fatal("前置条件：未撤销时快照的跳过应有效")
	}

	svc.Runtime.UnmarkTrafficResetPending(7, gen)

	if svc.Runtime.resetSkipValid(7, taken[7]) {
		t.Fatal("撤销后旧快照的跳过必须失效，否则会丢弃一轮真实用量")
	}
	if taken := svc.Runtime.takePendingTrafficResets(); len(taken) != 0 {
		t.Fatalf("撤销后不应再有待协调标记，实际 %v", taken)
	}
	svc.Runtime.UnmarkTrafficResetPending(999, 0)
}

func TestUnmarkOnlyRevokesOwnGeneration(t *testing.T) {
	svc := newTestServices(t, nil)

	genA := svc.Runtime.MarkTrafficResetPending(1)
	takenA := svc.Runtime.takePendingTrafficResets()
	genB := svc.Runtime.MarkTrafficResetPending(1)
	if genB <= genA {
		t.Fatalf("前置条件：后登记的代次应更大（%d ≤ %d）", genB, genA)
	}

	svc.Runtime.UnmarkTrafficResetPending(1, genA)

	if svc.Runtime.resetSkipValid(1, takenA[1]) {
		t.Fatal("A 的快照跳过必须失效（它自己的清零没写进去）")
	}
	left := svc.Runtime.takePendingTrafficResets()
	if left[1] != genB {
		t.Fatalf("B 的登记必须保留，实际 %v（期望代次 %d）", left, genB)
	}
	if !svc.Runtime.resetSkipValid(1, genB) {
		t.Fatal("B 的跳过必须仍然有效，否则 B 清零前的旧增量会被加回")
	}
}

func TestSetQuotaExceededIfVer(t *testing.T) {
	svc := newTestServices(t, nil)

	stale := svc.Runtime.GuardVer()
	svc.Runtime.BumpGuardVer()

	if ok := svc.Runtime.SetQuotaExceededIfVer(1, false, stale); ok {
		t.Fatal("旧版本号的条件写应被拒绝")
	}
	if svc.Runtime.IsQuotaExceeded(1) {
		t.Fatal("被拒绝的写入不应改动标记")
	}

	if ok := svc.Runtime.SetQuotaExceededIfVer(1, true, svc.Runtime.GuardVer()); !ok {
		t.Fatal("当前版本号的条件写应成功")
	}
	if !svc.Runtime.IsQuotaExceeded(1) {
		t.Fatal("条件写成功后标记应生效")
	}
}

func TestRefreshQuotaFlagsYieldsWhenBumped(t *testing.T) {
	svc := newTestServices(t, nil)

	for i := 0; i < 50; i++ {
		u := &model.User{Username: fmt.Sprintf("bump%d", i), Password: "not-used",
			Status: model.UserStatusActive}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				svc.Runtime.BumpGuardVer()
			}
		}
	}()

	err := svc.refreshQuotaFlags()
	close(stop)
	<-done

	if err != nil {
		t.Fatalf("被打断的刷新不返回错误，只是不宣告就绪: %v", err)
	}
	if svc.Runtime.AccessGuardReady() {
		t.Fatal("版本全程被打断的刷新不得宣告就绪，否则插件会按不完整的标记放行")
	}

	if err := svc.refreshQuotaFlags(); err != nil {
		t.Fatalf("正常刷新失败: %v", err)
	}
	if !svc.Runtime.AccessGuardReady() {
		t.Fatal("版本稳定的刷新必须宣告就绪")
	}
	if !svc.LoadAccessGuard() {
		t.Fatal("就绪后的加载应报告成功")
	}
}

func TestEnsureTrafficPeriodKeepsPreloadedGroup(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "small", AllowProtocols: "tcp", TrafficQuota: 100}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	u := &model.User{Username: "preload", Password: "not-used", Status: model.UserStatusActive,
		GroupID: g.ID, TrafficUsed: 50,
		TrafficResetAt: time.Now().Add(-25 * time.Hour)}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("traffic_reset_at", time.Now().AddDate(0, 1, 0)).Error; err != nil {
		t.Fatal(err)
	}

	svc.EnsureTrafficPeriod(u)

	if u.Group == nil || u.Group.ID != g.ID {
		t.Fatal("并发重读后的用户应保留分组关联")
	}
}
