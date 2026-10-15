package monitor

import (
	"strings"
	"syscall"
	"testing"
)

// TestParseSelfStatHandlesCommWithSpaces 验证进程名含空格与括号时不会错位。
//
// /proc/self/stat 的第 2 个字段是进程名，被括号包裹且**可以包含空格与括号**。
// 直接用 strings.Fields 切分会让其后的 utime / stime / rss 全部错位——
// 而错位后仍能解析出数字，只是数字来自别的字段，不会报错。
// 所以这条必须有测试守着。
func TestParseSelfStatHandlesCommWithSpaces(t *testing.T) {
	// 构造一条真实格式的 stat：comm 里带空格和括号。
	// 括号后共 22 个字段（state 到 rss），这里只填充必要的几个。
	rest := []string{
		"S",    // 1  state
		"1",    // 2  ppid
		"0",    // 3  pgrp
		"0",    // 4  session
		"0",    // 5  tty_nr
		"0",    // 6  tpgid
		"0",    // 7  flags
		"0",    // 8  minflt
		"0",    // 9  cminflt
		"0",    // 10 majflt
		"0",    // 11 cmajflt
		"120",  // 12 utime
		"80",   // 13 stime
		"0",    // 14 cutime
		"0",    // 15 cstime
		"20",   // 16 priority
		"0",    // 17 nice
		"4",    // 18 num_threads
		"0",    // 19 itrealvalue
		"1000", // 20 starttime
		"9999", // 21 vsize
		"500",  // 22 rss（页）
	}
	raw := "1234 (my (weird) process name) " + strings.Join(rest, " ")

	cpu, rss := parseSelfStat(raw)

	if cpu != 200 { // 120 + 80
		t.Errorf("CPU 时间解析错误：got %d, want 200", cpu)
	}
	// rss 单位是页，需乘页面大小，所以只校验「非零且是页面大小的整数倍」。
	if rss == 0 {
		t.Fatal("RSS 不应为 0")
	}
	if rss%uint64(syscall.Getpagesize()) != 0 {
		t.Errorf("RSS 应为页面大小的整数倍：got %d", rss)
	}
}

// TestParseSelfStatRejectsShortInput 验证字段不足时安全返回 0。
func TestParseSelfStatRejectsShortInput(t *testing.T) {
	for _, in := range []string{"", "no-parens", "1 (x) S", "1 (x) S 1 2"} {
		if cpu, rss := parseSelfStat(in); cpu != 0 || rss != 0 {
			t.Errorf("输入 %q 应返回 0/0，got %d/%d", in, cpu, rss)
		}
	}
}

// TestCPUPercent 验证使用率的计算与边界。
//
// 这里最容易错的是 iowait 的归属：iowait 期间 CPU 实际空闲，
// 若不算进 idle，磁盘等待会被误报成 CPU 繁忙（做 IO 的机器上能差出几十个百分点）。
// readCPUCounters 已把 iowait 累加进 idle，本函数只负责算比例。
func TestCPUPercent(t *testing.T) {
	cases := []struct {
		name                        string
		prevTotal, prevIdle         uint64
		curTotal, curIdle           uint64
		want                        float64
	}{
		{"空闲 70%", 1000, 500, 2000, 1200, 30},
		{"全忙", 1000, 500, 2000, 500, 100},
		{"全闲", 1000, 500, 2000, 1500, 0},
		{"计数器未推进", 1000, 500, 1000, 500, 0},
		{"计数器回绕", 2000, 1000, 1000, 500, 0},
		// 异常输入：idle 增量大于总增量（内核读数的瞬时不一致）
		{"idle 超过 total 时钳制", 1000, 500, 1100, 900, 0},
	}
	for _, tc := range cases {
		got := cpuPercent(tc.prevTotal, tc.prevIdle, tc.curTotal, tc.curIdle)
		if got != tc.want {
			t.Errorf("%s: got %.1f, want %.1f", tc.name, got, tc.want)
		}
	}
}

// TestRateOfHandlesCounterReset 验证计数器回绕时返回 0 而不是负速率。
//
// 网卡重置、容器重启都会让累计计数器归零。若直接相减会得到巨大的负值，
// 图表上表现为一根向下的尖刺，管理员会以为出了故障。
func TestRateOfHandlesCounterReset(t *testing.T) {
	if got := rateOf(100, 200, 10); got != 10 {
		t.Errorf("正常增量：got %v, want 10", got)
	}
	if got := rateOf(200, 100, 10); got != 0 {
		t.Errorf("计数器回绕应返回 0，got %v", got)
	}
	if got := rateOf(100, 200, 0); got != 0 {
		t.Errorf("时间差为 0 应返回 0，got %v", got)
	}
}
