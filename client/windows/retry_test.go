package main

import (
	"testing"
	"time"
)

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
	if d := retryDelay(0); d != retryDelay(1) {
		t.Fatalf("次数非法（0）时应回落到首次退避，实际 %v", d)
	}
}

func TestRetryGateBlocksAfterFailure(t *testing.T) {
	a := &App{retries: map[uint]*retryState{}}

	if !a.retryAllowed(1) {
		t.Fatal("没有失败记录时应允许拉起")
	}

	a.noteStartFailure(1, "mc", "启动失败")
	if a.retryAllowed(1) {
		t.Fatal("刚失败之后应处于退避中，否则下一轮同步会立刻再拉一次")
	}

	a.clearRetry(1)
	if !a.retryAllowed(1) {
		t.Fatal("清掉退避后应立即可拉起")
	}
}

func TestReconnectStartDoesNotResetTimer(t *testing.T) {
	a := &App{connectAt: map[uint]time.Time{}}

	a.markConnectStart(1)
	first := a.connectAt[1]
	time.Sleep(2 * time.Millisecond)
	a.markReconnectStart(1)
	if !a.connectAt[1].Equal(first) {
		t.Fatal("重连路径不该覆盖已有起点：否则计时永远停在「刚等了几秒」")
	}

	a.markConnectStart(1)
	if !a.connectAt[1].After(first) {
		t.Fatal("重新拉起进程后应重新计时")
	}
	if _, ok := a.connectAt[2]; ok {
		t.Fatal("不该给别的隧道记起点")
	}
}

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
