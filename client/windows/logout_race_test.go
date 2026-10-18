package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

// testManager 造一个「找不到 frpc」的进程管理器。
//
// 传空串的话 New 会去 PATH 上找真的 frpc，测试的行为就取决于这台机器上
// 装没装它；指定一个不存在的路径，行为才是确定的。
func testManager(t *testing.T) *frpc.Manager {
	t.Helper()
	return frpc.New(filepath.Join(t.TempDir(), "no-such-frpc.exe"))
}

// 这一组守的是「退出登录与迟到回调」以及「跨账号日志」两条边界。
//
// 两处的共同点是：症状都不是崩溃，而是**状态被悄悄改错**——隧道刚连上
// 又被标成未连接、新账号里冒出旧账号的日志。靠手动点点不出来，只能把
// 顺序构造出来断言。

// TestExitCallbackIgnoresOtherAccountGeneration 覆盖「旧账号的退出回调改新账号状态」。
//
// 退出登录会停进程、再等回调，但等待有上限；超时之后那个回调仍会执行。
// 它描述的是上一个账号的进程，而 registered / retries 都是**当前账号**的
// 运行态：照旧处理就会把新账号刚连上的隧道标成未连接、并给它记一笔
// 根本不属于它的失败。
func TestExitCallbackIgnoresOtherAccountGeneration(t *testing.T) {
	now := time.Now()
	a := &App{
		mgr:          testManager(t),
		registered:   map[uint]bool{1: true},
		registeredAt: map[uint]time.Time{1: now},
		retries:      map[uint]*retryState{},
		connectAt:    map[uint]time.Time{},
		// 记账代次 0 是「上一个账号」启动的，而当前账号代次已经是 1。
		startGen:       map[uint]uint64{1: 0},
		authGeneration: 1,
	}

	a.onTunnelExit(1, "mc", errors.New("exit status 1"), false)

	if !a.registered[1] {
		t.Fatal("旧账号进程的退出回调不得清掉当前账号的「已注册」标记")
	}
	if len(a.retries) != 0 {
		t.Fatalf("旧账号进程的退出回调不得给当前账号记失败/退避，实际 %+v", a.retries)
	}
}

// TestExitCallbackHandlesOwnAccountProcess 确认代次校验没有误伤正常路径。
//
// 同一账号下启动的进程退出时，registered 必须照常清掉、失败照常记：
// 否则界面会一直显示「运行中」，而进程早就没了。
func TestExitCallbackHandlesOwnAccountProcess(t *testing.T) {
	a := &App{
		mgr:            testManager(t),
		registered:     map[uint]bool{},
		registeredAt:   map[uint]time.Time{},
		retries:        map[uint]*retryState{},
		connectAt:      map[uint]time.Time{},
		authGeneration: 3,
	}
	// 与生产路径一致：先记账（取当前代次），再让回调到来。
	a.markStartGeneration(1)
	a.setTunnelRegistered(1, true)

	a.onTunnelExit(1, "mc", errors.New("exit status 1"), false)

	if a.registered[1] {
		t.Fatal("本账号进程退出后必须清掉「已注册」，否则界面一直显示运行中")
	}
	if a.retries[1] == nil {
		t.Fatal("非请求退出应进入退避，否则下一轮同步立刻又拉起一个必然再退出的进程")
	}
}

// TestExitCallbackSkipsWhenNoRecord 覆盖「记账已被清掉」这一路。
//
// 退出登录与 pruneTunnelState 都会清 startGen。此时回调手上的信息不足以
// 证明进程属于当前账号，只能什么都不做——下一轮同步会据实对账。
func TestExitCallbackSkipsWhenNoRecord(t *testing.T) {
	now := time.Now()
	a := &App{
		mgr:          testManager(t),
		registered:   map[uint]bool{7: true},
		registeredAt: map[uint]time.Time{7: now},
		retries:      map[uint]*retryState{},
		connectAt:    map[uint]time.Time{},
		// 刻意不建 startGen：模拟已被 resetPerAccountState 清空。
	}

	a.onTunnelExit(7, "mc", nil, false)

	if !a.registered[7] {
		t.Fatal("查无启动记账时不得改动运行态：无法证明它属于当前账号")
	}
	if len(a.retries) != 0 {
		t.Fatalf("查无启动记账时不得记失败，实际 %+v", a.retries)
	}
}

// TestLogoutFlipsGenerationAndDropsStartRecords 覆盖登录态切换时的清理。
//
// 两件事必须一起发生，且顺序固定：
//   - authGeneration 前进（此后任何旧回调都过不了代次校验）；
//   - startGen 清空（迟到回调查不到记账，同样不会动手）。
//
// 顺序反了（先清 startGen 再翻代次）也能过校验，但中间那一刻新旧混在一起，
// 所以这里只断言结果状态，同时确认日志代次确实前进并被带进了 State。
func TestLogoutFlipsGenerationAndDropsStartRecords(t *testing.T) {
	withTempConfigDir(t)
	panel, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, panel)

	a.markStartGeneration(5)
	before := a.currentLogEpoch()

	cleanup := func() error { return nil }
	if _, err := a.logout(cleanup, cleanup); err != nil {
		t.Fatalf("退出登录失败: %v", err)
	}

	a.mu.RLock()
	gen := a.authGeneration
	_, hasRecord := a.startGen[5]
	a.mu.RUnlock()

	if gen == 0 {
		t.Fatal("退出登录必须推进账号代次，否则迟到的回调仍会被当成当前账号的")
	}
	if hasRecord {
		t.Fatal("退出登录必须清掉启动记账，迟到的回调不能拿旧记录去改新账号状态")
	}

	want := before + 1
	if got := a.currentLogEpoch(); got != want {
		t.Fatalf("清空日志后代次应为 %d，实际 %d", want, got)
	}
	// GetState 必须把同一个代次带出去：前端靠它丢弃跨账号的旧批次。
	if got := a.GetState().LogEpoch; got != want {
		t.Fatalf("State.LogEpoch = %d，期望 %d：前端拿不到新代次就挡不住旧日志", got, want)
	}
}

// TestGetStateCarriesLogEpoch 覆盖「清空日志后状态里的代次没跟上」。
//
// 前端在清空时可拿到 ClearLogs 的返回值，但**接入/刷新**这些路径只拿到
// State；State 里没有代次，前端就只能靠自己累加，一旦漏一次，
// 之后每一批日志都会因为代次对不上被整批丢弃——日志区再也不动。
func TestGetStateCarriesLogEpoch(t *testing.T) {
	// 让数据目录落在临时目录里：GetState 会顺带解析隧道配置目录。
	withTempConfigDir(t)
	a := &App{mgr: testManager(t)}

	if got := a.GetState().LogEpoch; got != 0 {
		t.Fatalf("未清空过时代次应为 0，实际 %d", got)
	}
	cleared := a.ClearLogs()
	if got := a.GetState().LogEpoch; got != cleared.Epoch {
		t.Fatalf("State.LogEpoch = %d，与 ClearLogs 返回的 %d 不一致", got, cleared.Epoch)
	}
}

// TestPruneTunnelStateDropsStartRecord 覆盖「服务端已删除的隧道留下启动记账」。
//
// 记账是按隧道 id 存的一个 uint64，隧道被删掉之后再也没有机会被读到；
// 反复「建了、删掉」会让它随进程寿命一直长下去。
func TestPruneTunnelStateDropsStartRecord(t *testing.T) {
	a := &App{
		startGen:      map[uint]uint64{1: 1, 2: 1},
		tunnelErrs:    map[uint]tunnelErr{},
		retries:       map[uint]*retryState{},
		applied:       map[uint]string{},
		cfgRev:        map[uint]string{},
		cleanupWarned: map[uint]bool{},
		registered:    map[uint]bool{},
		registeredAt:  map[uint]time.Time{},
		errEmitAt:     map[uint]time.Time{},
		connectAt:     map[uint]time.Time{},
	}

	a.pruneTunnelState(map[uint]bool{1: true})

	a.mu.RLock()
	defer a.mu.RUnlock()
	if _, ok := a.startGen[1]; !ok {
		t.Fatal("仍然存在的隧道不该被清掉启动记账")
	}
	if _, ok := a.startGen[2]; ok {
		t.Fatal("服务端已删除的隧道应清掉启动记账，否则这张表会随「建了又删」一直长")
	}
}

// TestStateSeqMonotonicAndCarriedInState 覆盖「状态事件序号必须单调且随状态下发」。
//
// 前端靠 (auth_gen, state_seq) 的字典序丢弃乱序事件（见 State.StateSeq）。
// 序号不单调，或 GetState 不带它，前端就没有排序依据——退出登录后迟到的
// 「已登录」事件会被当成最新状态，界面闪回一次登录后的界面。
//
// 这里直接调 snapshotForEmit（emitState 的取号路径）：它不依赖 a.ctx，
// 而 EventsEmit 需要真实的 Wails 上下文，单测里起不来。
func TestStateSeqMonotonicAndCarriedInState(t *testing.T) {
	withTempConfigDir(t)
	a := &App{mgr: testManager(t)}

	var last uint64
	for i := 0; i < 5; i++ {
		seq, _, st := a.snapshotForEmit()
		if seq <= last {
			t.Fatalf("第 %d 次取号 = %d，未超过上一次的 %d：前端无法排序", i+1, seq, last)
		}
		last = seq
		if st.StateSeq != seq {
			t.Fatalf("快照里的 StateSeq = %d，与本次取到的 %d 不一致", st.StateSeq, seq)
		}
	}

	// GetState 不消耗序号，但必须带出**当前**值：前端拿快照与事件比较时，
	// 快照的序号不能凭空前进（否则每次刷新都会让在途的合法事件被判旧）。
	before := a.GetState().StateSeq
	if got := a.GetState().StateSeq; got != before {
		t.Fatalf("GetState 不该推进序号：连续两次读到 %d 与 %d", before, got)
	}
	if before != last {
		t.Fatalf("GetState 的序号 = %d，期望等于最后一次取号 %d", before, last)
	}
}

// TestLogoutAdvancesAuthGenSoStaleEventsAreDropped 覆盖「登出后旧账号的事件
// 无论何时到达都进不来」。
//
// 这是缺陷 7 的核心：光有序号不够。回调若在登出**之后**才取号，它会拿到
// 比登出推送更大的序号——前端按序号比较会接受它，界面在用户已经退出后
// 又闪回已登录。账号代次补上这一维：登出让它前进，旧回调持有的代次更小，
// 前端按字典序整份丢弃。
func TestLogoutAdvancesAuthGenSoStaleEventsAreDropped(t *testing.T) {
	withTempConfigDir(t)
	panel, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, panel)

	// 登出前先取一份，模拟「旧账号下的状态」。
	_, oldGen, oldState := a.snapshotForEmit()

	cleanup := func() error { return nil }
	if _, err := a.logout(cleanup, cleanup); err != nil {
		t.Fatalf("退出登录失败: %v", err)
	}

	_, newGen, newState := a.snapshotForEmit()

	if newGen <= oldGen {
		t.Fatalf("退出登录必须推进账号代次：登出前 %d，登出后 %d", oldGen, newGen)
	}
	// 前端的丢弃判据是字典序 (auth_gen, state_seq)：旧代次必须整份判旧，
	// 哪怕它的序号更大。
	if oldGen >= newGen {
		t.Fatal("旧账号代次必须小于新账号代次，否则前端会把迟到事件当成最新的")
	}
	if oldState.AuthGen != oldGen || newState.AuthGen != newGen {
		t.Fatalf("State.AuthGen 未与代次同步：旧 %d/%d，新 %d/%d",
			oldState.AuthGen, oldGen, newState.AuthGen, newGen)
	}
	if newState.LoggedIn {
		t.Fatal("登出后的状态必须是未登录：否则界面不会切回登录页")
	}
}

// TestStaleStateAfterLogoutIsOlder 用前端同一套比较规则验证丢弃判据。
//
// 前端是 JS 不便单测，但判据本身是纯函数（字典序比较），在 Go 侧复刻一份
// 就能守住「改动比较规则时两端会不一致」这个风险。
func TestStaleStateAfterLogoutIsOlder(t *testing.T) {
	// 与 App.vue 的 stateIsStale 完全一致的实现。
	stale := func(prevGen, prevSeq, gen, seq uint64) bool {
		if gen != prevGen {
			return gen < prevGen
		}
		return seq < prevSeq
	}

	// 旧账号（gen=1）的迟到事件，序号比登出推送（gen=2, seq=9）还大。
	// 按字典序必须判旧——这正是「只比序号」做不到的。
	if !stale(2, 9, 1, 100) {
		t.Fatal("旧账号代次的事件必须判旧，哪怕它的序号更大：否则界面会闪回已登录")
	}
	// 同代次内序号更小的判旧。
	if !stale(2, 9, 2, 8) {
		t.Fatal("同代次内序号更小的事件必须判旧")
	}
	// 同代次内序号相等不算旧（同一次推送可能被投递两次）。
	if stale(2, 9, 2, 9) {
		t.Fatal("序号相等应视为重复投递，重复应用同一份状态无害")
	}
	// 新账号代次的事件必须接受，哪怕序号基线重来后更小。
	if stale(2, 9, 3, 1) {
		t.Fatal("新账号代次的事件必须接受：序号基线随账号重来")
	}
}
