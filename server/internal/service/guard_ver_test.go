package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「后台刷新与管理员直写内存准入标记之间的竞态」，
// 以及「清零协调标记必须与数据库事务同生共死」。

// TestGuardVerBlocksStaleSnapshotWrite 覆盖「旧快照不得覆盖管理员刚写的标记」。
//
// 后台刷新按「取版本号 → 读库 → 逐个写标记」三步走；管理员（调低配额、
// 禁用账号）在这中间改动时会把标记直接写进内存，并递增版本号。刷新随后
// 按旧版本号做条件写必须整体让路——否则插件热路径只认内存，管理员刚置的
// 超额/禁用标记会被旧快照清掉，且只要后续采集持续失败就一直错下去。
//
// 按真实交错顺序复现：刷新先取版本号（stale），管理员再 bump 并写标记，
// 最后旧快照尝试回写。
func TestGuardVerBlocksStaleSnapshotWrite(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "guardver", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 1) 后台刷新取走版本号（此时读到的库快照里用户没超额）。
	stale := svc.Runtime.GuardVer()

	// 2) 管理员路径直写：调低配额并置超额（BumpGuardVer + Set...）。
	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)

	// 3) 旧快照回写：版本号不匹配，必须整体让路。
	if ok := svc.Runtime.SetGuardFlagsIfVer(u.ID, false, false, stale); ok {
		t.Fatal("旧版本号的条件写应被拒绝")
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("管理员的超额标记被旧快照清掉了")
	}

	// 版本一致时条件写照常生效：新一轮刷新用新快照覆盖。
	if ok := svc.Runtime.SetGuardFlagsIfVer(u.ID, false, false, svc.Runtime.GuardVer()); !ok {
		t.Fatal("当前版本号的条件写应成功")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("新快照应能正常刷新标记")
	}
}

// TestFlushTrafficKeepsMarkOnTxFailure 覆盖「采集事务失败后标记原样保留」。
//
// 快照（skipUsers）不再摘除标记：事务失败时标记原样留在 map 里，
// 下一轮继续按它跳过——基线还停在旧值、增量没落库，丢掉标记就会把
// 清零前的旧增量原样加回（「清零完又冒出来」）。
func TestFlushTrafficKeepsMarkOnTxFailure(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	svc.Runtime.MarkTrafficResetPending(tun.UserID)

	// 迫使事务失败：日明细表不存在，带流量的隧道增量写到它时必然报错。
	if err := svc.DB.Migrator().DropTable(&model.TrafficDaily{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	err := svc.flushTraffic(
		map[uint]*tunnelDelta{tun.ID: {in: 100, out: 100}},
		map[uint]int64{tun.UserID: 500},
		map[uint]uint{tun.ID: tun.UserID},
		map[string]trafficPair{}, false,
	)
	if err == nil {
		t.Fatal("日明细表缺失时落库应失败")
	}

	// 标记必须还在（快照不摘除、失败不丢失）。
	taken := svc.Runtime.takePendingTrafficResets()
	if len(taken) != 1 {
		t.Fatalf("事务失败后清零标记应保留在内存，实际 %v", taken)
	}

	// 下一轮成功采集：旧增量 500 仍要被跳过；成功后标记按代次摘除，
	// 之后的轮次恢复正常。
	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false,
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
		nil, map[string]trafficPair{}, false,
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 300 {
		t.Fatalf("消费后的新增量应正常累加，实际 %d（期望 300）", got)
	}
}

// TestConsumePreservesRemarkedGeneration 覆盖「消费只摘除代次未变的标记」。
//
// 采集事务进行期间管理员又清零了同一用户（代次推进）：成功提交后，
// 旧代次被消费，但新登记的代次必须保留——否则第二轮的旧增量会漏掉。
func TestConsumePreservesRemarkedGeneration(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.MarkTrafficResetPending(1)
	taken := svc.Runtime.takePendingTrafficResets()

	// 事务进行期间，管理员再次清零：代次推进。
	svc.Runtime.MarkTrafficResetPending(1)

	svc.Runtime.consumePendingTrafficResets(taken)

	left := svc.Runtime.takePendingTrafficResets()
	if len(left) != 1 || !svc.Runtime.resetSkipValid(1, left[1]) {
		t.Fatalf("新登记的代次应保留且有效，实际 %v", left)
	}
}

// TestUnmarkInvalidatesTakenSnapshot 覆盖「撤销同时作废已取走的旧代次」。
//
// AdminResetUserTraffic 登记标记、清零写库失败后撤销：此时标记可能已被
// 采集器的快照取走（甚至正在事务里按它跳过）。撤销必须让旧代次的跳过
// 失效，否则一次失败的清零仍会丢弃一轮**真实**用量——那不是旧增量。
func TestUnmarkInvalidatesTakenSnapshot(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.MarkTrafficResetPending(7)
	taken := svc.Runtime.takePendingTrafficResets()
	if !svc.Runtime.resetSkipValid(7, taken[7]) {
		t.Fatal("前置条件：未撤销时快照的跳过应有效")
	}

	// 登记方撤销：清零写库失败。
	svc.Runtime.UnmarkTrafficResetPending(7)

	// 已取走的旧代次即刻失效；map 里的标记也已删除。
	if svc.Runtime.resetSkipValid(7, taken[7]) {
		t.Fatal("撤销后旧快照的跳过必须失效，否则会丢弃一轮真实用量")
	}
	if taken := svc.Runtime.takePendingTrafficResets(); len(taken) != 0 {
		t.Fatalf("撤销后不应再有待协调标记，实际 %v", taken)
	}
	// 未登记的用户撤销也不报错（幂等）。
	svc.Runtime.UnmarkTrafficResetPending(999)
}

// TestRefreshQuotaFlagsYieldsWhenBumped 覆盖「被打断的刷新不得宣告就绪」。
//
// 后台刷新逐用户条件写期间，管理操作持续递增版本号：剩余用户的写入全部
// 让路，整轮不完整。此时若仍标记 guardReady，插件会按「内存完整」放行
// 实际上没有标记的账号；正确行为是不宣告就绪（插件继续 fail-closed），
// 并在管理操作停止后的下一轮刷新里恢复正常。
func TestRefreshQuotaFlagsYieldsWhenBumped(t *testing.T) {
	svc := newTestServices(t, nil)

	// 用户多一些，拉长单轮耗时，让并发 bump 几乎必然插进每一轮。
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

	// 管理操作停止后：刷新完整走完，恢复正常就绪。
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

// TestEnsureTrafficPeriodKeepsPreloadedGroup 覆盖「并发重读保留分组关联」。
//
// 条件更新未命中时按最终状态重读用户：丢掉 Preload("Group") 的话，
// 重读后的对象没有分组，QuotaExceeded 按默认分组配额判定，
// 低配额用户在周期重置瞬间可能被误判为未超额。
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

	// 快照读完后，「并发方」改动了 reset_at（等价于管理员清零）。
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("traffic_reset_at", time.Now().AddDate(0, 1, 0)).Error; err != nil {
		t.Fatal(err)
	}

	svc.EnsureTrafficPeriod(u)

	// 重读后的对象必须仍挂着分组，配额判定走的是用户自己的套餐。
	if u.Group == nil || u.Group.ID != g.ID {
		t.Fatal("并发重读后的用户应保留分组关联")
	}
}
