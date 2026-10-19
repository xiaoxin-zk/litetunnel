package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

func testManager(t *testing.T) *frpc.Manager {
	t.Helper()
	return frpc.New(filepath.Join(t.TempDir(), "no-such-frpc.exe"))
}

func TestExitCallbackIgnoresOtherAccountGeneration(t *testing.T) {
	now := time.Now()
	a := &App{
		mgr:            testManager(t),
		registered:     map[uint]bool{1: true},
		registeredAt:   map[uint]time.Time{1: now},
		retries:        map[uint]*retryState{},
		connectAt:      map[uint]time.Time{},
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

func TestExitCallbackHandlesOwnAccountProcess(t *testing.T) {
	a := &App{
		mgr:            testManager(t),
		registered:     map[uint]bool{},
		registeredAt:   map[uint]time.Time{},
		retries:        map[uint]*retryState{},
		connectAt:      map[uint]time.Time{},
		authGeneration: 3,
	}
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

func TestExitCallbackSkipsWhenNoRecord(t *testing.T) {
	now := time.Now()
	a := &App{
		mgr:          testManager(t),
		registered:   map[uint]bool{7: true},
		registeredAt: map[uint]time.Time{7: now},
		retries:      map[uint]*retryState{},
		connectAt:    map[uint]time.Time{},
	}

	a.onTunnelExit(7, "mc", nil, false)

	if !a.registered[7] {
		t.Fatal("查无启动记账时不得改动运行态：无法证明它属于当前账号")
	}
	if len(a.retries) != 0 {
		t.Fatalf("查无启动记账时不得记失败，实际 %+v", a.retries)
	}
}

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
	if got := a.GetState().LogEpoch; got != want {
		t.Fatalf("State.LogEpoch = %d，期望 %d：前端拿不到新代次就挡不住旧日志", got, want)
	}
}

func TestGetStateCarriesLogEpoch(t *testing.T) {
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

	before := a.GetState().StateSeq
	if got := a.GetState().StateSeq; got != before {
		t.Fatalf("GetState 不该推进序号：连续两次读到 %d 与 %d", before, got)
	}
	if before != last {
		t.Fatalf("GetState 的序号 = %d，期望等于最后一次取号 %d", before, last)
	}
}

func TestLogoutAdvancesAuthGenSoStaleEventsAreDropped(t *testing.T) {
	withTempConfigDir(t)
	panel, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, panel)

	_, oldGen, oldState := a.snapshotForEmit()

	cleanup := func() error { return nil }
	if _, err := a.logout(cleanup, cleanup); err != nil {
		t.Fatalf("退出登录失败: %v", err)
	}

	_, newGen, newState := a.snapshotForEmit()

	if newGen <= oldGen {
		t.Fatalf("退出登录必须推进账号代次：登出前 %d，登出后 %d", oldGen, newGen)
	}
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

func TestStaleStateAfterLogoutIsOlder(t *testing.T) {
	stale := func(prevGen, prevSeq, gen, seq uint64) bool {
		if gen != prevGen {
			return gen < prevGen
		}
		return seq < prevSeq
	}

	if !stale(2, 9, 1, 100) {
		t.Fatal("旧账号代次的事件必须判旧，哪怕它的序号更大：否则界面会闪回已登录")
	}
	if !stale(2, 9, 2, 8) {
		t.Fatal("同代次内序号更小的事件必须判旧")
	}
	if stale(2, 9, 2, 9) {
		t.Fatal("序号相等应视为重复投递，重复应用同一份状态无害")
	}
	if stale(2, 9, 3, 1) {
		t.Fatal("新账号代次的事件必须接受：序号基线随账号重来")
	}
}
