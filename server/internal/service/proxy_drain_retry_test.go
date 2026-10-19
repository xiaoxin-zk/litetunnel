package service

// 这个文件守的是「断流失败之后还有没有下文」——缺陷 1 与缺陷 5 的共同后果：
//
//   - frps 不可用导致这次断流没做成时，意图必须**落库**，不能只留一行日志：
//     账号在面板上已经禁用/删除，数据流却还在转发，重启后连线索都没有；
//   - frps 恢复之后后台重试要把残留补关掉，并把待办清掉；
//   - 期间账号被重新启用时，那条待办必须作废——继续关就是把刚放行的人踢下线，
//     用户侧只看到「连上又断」，从来没有哪个日志会说是断流造成的；
//   - 一轮断流只拉一次批量列表，而不是每条代理重拉一次（缺陷 5：15 秒预算
//     全花在分页抓取上，N 条代理只关掉一部分）。
//
// 全部离线运行：假 frps 用 httptest（见 account_lifecycle_test.go 的
// fakeFrpsProxies），数据库用临时 sqlite（见 newTestServices）。

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// loadDrainPending 读该用户的断流待办；第二个返回值为 false 表示不存在。
//
// 用 Find + 长度判断而不是 First：First 在「不存在」时会把 GORM 的
// ErrRecordNotFound 打到测试日志里，而这里「不存在」是**正常断言**的一半。
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

// makeDrainDue 把待办的下次重试时间拨到过去。
//
// 真实退避起步就是 30 秒，用例不可能等；只改这一列，重试路径本身不变。
func makeDrainDue(t *testing.T, svc *Services, userID uint) {
	t.Helper()
	if err := svc.DB.Model(&model.ProxyDrainPending{}).Where("user_id = ?", userID).
		Update("next_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("把待办拨到到期失败: %v", err)
	}
}

// TestCloseUserProxiesPersistsPendingWhenFrpsUnavailable 覆盖缺陷 1 的落库那一半。
//
// 禁用账号时 frps 管理接口不可用：这次断流一条也关不掉，但**意图必须留下**。
// 以前这里只打印一行日志，进程一重启连这条线索都没了，而那些已经建立的
// 数据流不经过任何准入判断，会一直转发到客户端自己退出。
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

// TestProxyDrainWorkerClosesResidualAfterFrpsRecovers 覆盖缺陷 1 的补偿那一半。
//
// frps 恢复后，后台重试应当把残留的代理补关掉，并把待办清掉——这才是
// 「持久化」的意义。只落库不重试等于把一行垃圾留在库里。
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

// TestProxyDrainRetryAbandonsWhenAccountReEnabled 覆盖重试路径上的意图复核。
//
// 禁用 → frps 不可用（留下待办）→ 管理员又把账号重新启用。客户端随即重连、
// 用同样的名字重新注册。此时照着待办继续关，关掉的就是刚放行的人。
// 待办必须作废并删除，一条代理都不许动。
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
	// 客户端重连：同名代理，但已经是新实例（新的 clientID 与启动时间）。
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

// TestProxyDrainRetryUsesDeleteSemanticsWhenAccountRemoved 覆盖「禁用之后又删号」。
//
// 待办是按禁用意图登记的，但重试时 users 行已经不存在。此时不存在「重新启用」
// 的可能，也没有 state_version 可读——必须换成删号语义（前缀 + 实例身份）
// 把代理关干净，而不是因为「读不到版本」就放弃。
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
	// 删号：删除路径也会登记自己的意图（删号优先于禁用），本轮同样关不掉。
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

// TestProxyDrainRetrySkipsReRegisteredInstance 覆盖待办快照的身份比对。
//
// 待办里存的是「发现那一刻的实例身份」。重试时同名代理已经是别的实例
// （客户端重连后重新注册），按名字关就是误杀。判据与首次断流一致：
// 身份对不上就跳过，并视为「没有需要关的旧实例」，而不是残留。
func TestProxyDrainRetrySkipsReRegisteredInstance(t *testing.T) {
	svc := newTestServices(t, nil)
	const userID = 808
	name := FrpUserOf(userID) + ".mc"

	old := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t, proxyJSON(name, "client-new", time.Now().Unix()))
	f.install(svc)

	// 手工造一条待办：快照里是 client-old，而 frps 现在报的是 client-new。
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

// TestProxyDrainRetrySkipsProxiesStartedAfterIntent 覆盖重试路径的时间水位。
//
// 禁用意图没有实例快照可用时（首次断流连列表都没拉到），重试只能按前缀 +
// not_after 重新发现。重试发生在禁用之后，期间客户端可能已经重连并注册了
// 新实例：那类代理的 lastStartAt 晚于禁用时刻，必须跳过。
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

	// 期间客户端重连：旧代理消失，同名之外还多了一条禁用之后才启动的代理。
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

// TestProxyDrainSingleBatchListForManyProxies 覆盖缺陷 5。
//
// 以前每关一条代理都重拉一次全量列表：N 条代理就是 N+1 次分页抓取，frps 稍慢
// 就把 15 秒预算耗在拉列表上，一轮只关掉一部分。现在整轮复用一份带窗口的
// 快照，正常情况下只有 1 次列表请求。
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
	// 每关一条就重拉一次全量列表是缺陷 5 的形态：N 条代理 N+1 次分页抓取，
	// frps 稍慢就把 15 秒预算耗在拉列表上。
	//
	// 现在的预算是：
	//	1 次  发现候选（本轮快照）
	//	1 次  关闭后复查（缺陷 3：整轮末尾统一拉一次，确认同名代理有没有以
	//	      另一个实例身份重新出现；不能省，否则「误关了刚重连的新实例」
	//	      这件事没有任何痕迹）
	//	+ 1 次 余量：极慢机器上单轮关闭耗时可能超过快照窗口（2 秒），
	//	      中途 cache.lookup 会刷新一次快照
	//
	// 所以上限是 3，且必须与「代理条数」无关——那才是缺陷 5 的判据。
	// 把 6 条代理的常数写进断言，任何「按条数增长」的回归都会立刻超限。
	const maxLists = 3
	if n := f.listCount(); n > maxLists {
		t.Fatalf("一轮断流最多拉 %d 次批量列表（发现 1 + 复查 1 + 跨窗口余量 1），实际 %d 次；"+
			"若随代理条数增长就是缺陷 5 复发", maxLists, n)
	}
}

// TestProxyDrainBackoffGrowsAndCaps 断言退避的形状。
//
// 靠集成测试观察时间间隔既慢又不稳，所以退避单独做成纯函数（与 mailRetryDelay
// 同一形状）在这里直接断言：起步 30 秒、逐次翻倍、30 分钟封顶。
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

// TestProxyDrainRetrySchedulesBackoffThenExhausts 覆盖重试的收尾规则。
//
// 每失败一次要往后推一个退避并累加次数；到上限转终态、**保留记录**（删了之后
// 「这个已删除账号的代理可能还在跑」就再没有任何线索），并且不再被扫描。
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

	// 再失败一次：退避应变成 60 秒（翻倍）。
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

	// 差一次到上限：这一次之后应转终态并保留记录。
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

	// 终态记录不能再被扫出来重试：拨到到期后跑一轮，attempts 不该再变。
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

// TestProxyDrainPendingDeleteIntentWins 覆盖待办覆盖规则里最容易写反的一半。
//
// 一个用户只留一条待办，后来的意图覆盖先前的。删号意图必须**优先**于禁用意图：
// 账号都没了，「只断开禁用前那批流量」已经不需要区分，关干净就对了。反过来让
// 禁用意图覆盖删号意图，已删除账号的残留代理就失去了补偿机会——因为删除那条
// 意图已经被顶掉，而它才是「账号确实不会回来了」的唯一凭据。
//
// 这里直接调 recordProxyDrainPending 而不是走禁用/删除接口：接口会真的去关
// 代理（假 frps 关掉之后代理就从列表里消失），掩盖掉「谁占住了这一行」这件事。
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

	// 反向：已经登记了删号意图，再来一条状态代次更小的禁用意图（比如另一台
	// 实例上滞后的那次禁用），不许把它顶回去。返回空串正是「我没占住这一行」
	// 的凭据——调用方据此不认领、不拿旧令牌去收尾。
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

	// 收尾：用删号意图的令牌能删掉；用禁用路径的旧令牌删不掉。
	svc.clearProxyDrainPending(u.ID, disableFence)
	if _, ok := loadDrainPending(t, svc, u.ID); !ok {
		t.Fatal("旧令牌不该能删掉新意图的待办：那条待办还得继续跑")
	}
	svc.clearProxyDrainPending(u.ID, deleteFence)
	if _, ok := loadDrainPending(t, svc, u.ID); ok {
		t.Fatal("持有者用当前令牌应能清掉自己的待办")
	}
}

// TestProxyDrainRequestFromPendingUsesIntentAt 覆盖删除路径的时间水位来源。
//
// 删除路径没有「禁用生效时刻」（NotAfter=0），重试必须自己造一个水位：待办登记
// 之后才启动的代理只可能是客户端重连出来的新实例，关它是误杀。水位必须取
// **本次意图登记时刻**（IntentAt）而不是 CreatedAt——意图被覆盖时 CreatedAt
// 仍是第一次登记的时间，水位往前漂，而水位越早被当成「旧实例」的代理越多，
// 正好偏向误杀。
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

	// 老记录（IntentAt 还是 0）才退回 CreatedAt：没有别的可用信息时，
	// 宁可放宽水位也不能让重试完全不设边界。
	legacy := requestFromPending(model.ProxyDrainPending{
		UserID:    901,
		Deleted:   true,
		CreatedAt: created,
	})
	if !legacy.notAfter.Equal(created) {
		t.Fatalf("老记录的删除路径水位应退回 CreatedAt（%s），实际 %s",
			created.Format(time.RFC3339), legacy.notAfter.Format(time.RFC3339))
	}

	// 禁用路径的水位是 NotAfter，与 IntentAt 无关。
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
