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
