package service

import (
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

// TestFlushTrafficRestoresPendingResetOnTxFailure 覆盖「采集事务失败后标记归还」。
//
// 清零协调标记在事务外取走（skipUsers），事务失败时必须归还：基线还停在
// 旧值、增量没落库，下一轮会把清零前的旧增量原样加回——「清零完又冒出来」。
// 归还后紧接着一轮成功采集应继续按标记跳过该用户的旧增量。
func TestFlushTrafficRestoresPendingResetOnTxFailure(t *testing.T) {
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

	// 标记必须被归还（取走 → 失败 → 归还），而不是凭空消失。
	taken := svc.Runtime.takePendingTrafficResets()
	if !taken[tun.UserID] {
		t.Fatal("事务失败后清零标记应归还内存，等待下一轮成功采集消费")
	}
	// 取走归还的那份，模拟下一轮 flushTraffic 的取走动作。
	svc.Runtime.RestorePendingTrafficResets(taken)

	// 下一轮成功采集：旧增量 500 仍要被跳过——归还的标记继续生效。
	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false,
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 0 {
		t.Fatalf("归还的标记应继续抑制旧增量，实际用量 %d", got)
	}
}

// TestRestorePendingTrafficResetsMerges 覆盖「归还与并发登记合并」。
//
// 采集事务失败期间可能有新的管理员清零登记进来：归还必须合并而不是
// 覆盖，否则先登记的那份会被归还操作冲掉。
func TestRestorePendingTrafficResetsMerges(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.MarkTrafficResetPending(1)
	taken := svc.Runtime.takePendingTrafficResets()

	// 归还期间，管理员又清零了另一个用户。
	svc.Runtime.MarkTrafficResetPending(2)

	svc.Runtime.RestorePendingTrafficResets(taken)

	// 两份都必须在：先登记的没被覆盖，归还期间新登记的也没丢。
	merged := svc.Runtime.takePendingTrafficResets()
	if !merged[1] || !merged[2] {
		t.Fatalf("合并归还应同时保留旧取走与期间新登记的标记，实际 %v", merged)
	}
}

// TestUnmarkTrafficResetPending 覆盖「登记方写库失败时撤销标记」。
//
// AdminResetUserTraffic 登记标记后清零写库失败：标记必须撤销，否则后续
// 采集会错误丢弃一轮**真实**用量（那不是旧增量）。
func TestUnmarkTrafficResetPending(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.MarkTrafficResetPending(7)
	svc.Runtime.UnmarkTrafficResetPending(7)

	if taken := svc.Runtime.takePendingTrafficResets(); len(taken) != 0 {
		t.Fatalf("撤销后不应再有待协调标记，实际 %v", taken)
	}
	// 未登记的用户撤销也不报错（幂等）。
	svc.Runtime.UnmarkTrafficResetPending(999)
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
