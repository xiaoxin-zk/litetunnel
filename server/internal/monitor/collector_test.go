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
		name                string
		prevTotal, prevIdle uint64
		curTotal, curIdle   uint64
		want                float64
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

// TestSelfCPUPercent 验证面板进程自身的 CPU 占用算法。
//
// 这里最容易错的是分母：必须用同一段时间里的**系统**总增量。曾经传的是
// 「进程增量 / 进程增量」——只要进程用了一点 CPU 就恒等于 100%，
// 管理页上那个长期不变的 100% 就是这么来的。
//
// 期望值按「100% = 占满一个核」计算：进程增量 / 系统增量 × 核数 × 100。
// 系统增量在这段时间内恒等于 elapsed×cores×HZ，所以不必知道 HZ。
func TestSelfCPUPercent(t *testing.T) {
	cases := []struct {
		name                string
		prevProc, curProc   uint64
		prevTotal, curTotal uint64
		cores               int
		want                float64
	}{
		// 2 核 5 秒：系统增量 1000 jiffies（假设 HZ=100），进程用了 50 jiffies。
		{"2 核上占 10% 单核", 0, 50, 0, 1000, 2, 10},
		// 进程吃满一个核：500 jiffies / 1000 × 2 × 100 = 100%。
		{"占满一个核", 0, 500, 0, 1000, 2, 100},
		// 多核并行可以超过 100%。
		{"占满两个核", 0, 1000, 0, 1000, 2, 200},
		{"完全空闲", 100, 100, 1000, 2000, 4, 0},
		{"系统计数器未推进", 0, 50, 1000, 1000, 2, 0},
		{"进程计数器回绕", 100, 50, 1000, 2000, 2, 0},
		// 读数异常时钳制到 cores×100，不在界面上显示 800%。
		{"越界时钳制", 0, 5000, 0, 1000, 2, 200},
		{"核数非法时按 1 核", 0, 500, 0, 1000, 0, 50},
	}
	for _, tc := range cases {
		got := selfCPUPercent(tc.prevProc, tc.curProc, tc.prevTotal, tc.curTotal, tc.cores)
		if got != tc.want {
			t.Errorf("%s: got %.1f, want %.1f", tc.name, got, tc.want)
		}
	}
}

// TestNewNormalizesDiskPath 验证磁盘统计路径的默认值。
//
// 容器里 / 是镜像 overlay，所以路径必须可配（LT_MONITOR_DISK_PATH）；
// 配了空值/空白时退回根分区，而不是去 Statfs("")。
func TestNewNormalizesDiskPath(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if got := New(in).diskPath; got != "/" {
			t.Errorf("空路径 %q 应归一为 /，实际 %q", in, got)
		}
	}
	if got := New("/data").diskPath; got != "/data" {
		t.Errorf("应保留配置的路径，实际 %q", got)
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
