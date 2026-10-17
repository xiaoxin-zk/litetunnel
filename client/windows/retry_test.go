package main

import (
	"testing"
	"time"
)

// TestRetryDelayStartsAboveSyncInterval 是这套退避的核心约束。
//
// 起点若小于后台同步周期（20 秒），退避等于不存在：每个周期都会重新拉起
// 一次，日志被同样的失败刷屏，用户还以为客户端在「努力重连」。
func TestRetryDelayStartsAboveSyncInterval(t *testing.T) {
	if d := retryDelay(1); d <= syncInterval {
		t.Fatalf("首次退避 = %v，必须大于同步周期 %v，否则退避形同不存在", d, syncInterval)
	}
}

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	prev := time.Duration(0)
	for i := 1; i <= 20; i++ {
		d := retryDelay(i)
		if d < prev {
			t.Fatalf("第 %d 次的退避 %v 小于上一次 %v：退避必须单调不减", i, d, prev)
		}
		prev = d
	}
	if prev != 5*time.Minute {
		t.Fatalf("退避应封顶在 5 分钟，实际 %v", prev)
	}
	// 非法次数不该算出比首次更短或更长的怪值。
	if d := retryDelay(0); d != retryDelay(1) {
		t.Fatalf("次数非法（0）时应回落到首次退避，实际 %v", d)
	}
}

// TestRetryGateBlocksAfterFailure 覆盖闸门本身。
func TestRetryGateBlocksAfterFailure(t *testing.T) {
	a := &App{retries: map[uint]*retryState{}}

	if !a.retryAllowed(1) {
		t.Fatal("没有失败记录时应允许拉起")
	}

	a.noteStartFailure(1, "mc", "启动失败")
	if a.retryAllowed(1) {
		t.Fatal("刚失败之后应处于退避中，否则下一轮同步会立刻再拉一次")
	}

	// 用户主动点开时清退避：他刚修好问题，不该再等上一次失败的等待时间。
	a.clearRetry(1)
	if !a.retryAllowed(1) {
		t.Fatal("清掉退避后应立即可拉起")
	}
}

// TestReconnectStartDoesNotResetTimer 覆盖「已等待时长」的起点语义。
//
// 同步流程每轮都会对「服务端说离线、本机进程还在」的隧道调一次重连计时。
// 若每次都覆盖起点，界面上的时长会永远停在「刚等了几秒」，反而看不出
// 已经卡了多久——那正是这个诊断信息要回答的问题。
func TestReconnectStartDoesNotResetTimer(t *testing.T) {
	a := &App{connectAt: map[uint]time.Time{}}

	a.markConnectStart(1)
	first := a.connectAt[1]
	time.Sleep(2 * time.Millisecond)
	a.markReconnectStart(1)
	if !a.connectAt[1].Equal(first) {
		t.Fatal("重连路径不该覆盖已有起点：否则计时永远停在「刚等了几秒」")
	}

	// 进程被真正重新拉起时应当重新计时：那是新的一次连接。
	a.markConnectStart(1)
	if !a.connectAt[1].After(first) {
		t.Fatal("重新拉起进程后应重新计时")
	}
	if _, ok := a.connectAt[2]; ok {
		t.Fatal("不该给别的隧道记起点")
	}
}

// TestPruneTunnelStateClearsConnectAt 覆盖「服务端已删除的隧道留下计时条目」。
//
// 一条隧道反复「建了、连不上、删掉」时，它的连接起点没有任何机会再被
// 访问；不清就会随进程寿命一直留着。
func TestPruneTunnelStateClearsConnectAt(t *testing.T) {
	a := &App{connectAt: map[uint]time.Time{
		1: time.Now(),
		2: time.Now(),
	}}
	a.pruneTunnelState(map[uint]bool{2: true})
	if _, ok := a.connectAt[1]; ok {
		t.Fatal("服务端已不存在的隧道应清掉连接起点")
	}
	if _, ok := a.connectAt[2]; !ok {
		t.Fatal("仍然存在的隧道不该被清")
	}
}

// TestRegisteredClearsConnectTimer 覆盖「连上之后计时归零」。
func TestRegisteredClearsConnectTimer(t *testing.T) {
	a := &App{
		registered:   map[uint]bool{},
		registeredAt: map[uint]time.Time{},
		connectAt:    map[uint]time.Time{},
	}
	a.markConnectStart(1)
	a.setTunnelRegistered(1, true)
	if _, ok := a.connectAt[1]; ok {
		t.Fatal("注册成功后应清掉等待起点，否则下次掉线会显示一个从很久以前算起的时长")
	}
}

// TestRetryStateIsPerTunnel 确认退避按隧道隔离。
//
// 共用一份状态的话，一条隧道反复失败会把其他隧道的重试一起推迟——
// 而它们本来能正常工作。
func TestRetryStateIsPerTunnel(t *testing.T) {
	a := &App{retries: map[uint]*retryState{}}

	a.noteStartFailure(1, "mc", "启动失败")

	if a.retryAllowed(1) {
		t.Fatal("失败的隧道应处于退避中")
	}
	if !a.retryAllowed(2) {
		t.Fatal("另一条隧道不该受牵连")
	}
}
