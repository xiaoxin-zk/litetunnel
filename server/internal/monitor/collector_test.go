package monitor

import (
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestParseSelfStatHandlesCommWithSpaces(t *testing.T) {
	rest := []string{
		"S",
		"1",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"120",
		"80",
		"0",
		"0",
		"20",
		"0",
		"4",
		"0",
		"1000",
		"9999",
		"500",
	}
	raw := "1234 (my (weird) process name) " + strings.Join(rest, " ")

	cpu, rss := parseSelfStat(raw)

	if cpu != 200 {
		t.Errorf("CPU 时间解析错误：got %d, want 200", cpu)
	}
	if rss == 0 {
		t.Fatal("RSS 不应为 0")
	}
	if rss%uint64(syscall.Getpagesize()) != 0 {
		t.Errorf("RSS 应为页面大小的整数倍：got %d", rss)
	}
}

func TestParseSelfStatRejectsShortInput(t *testing.T) {
	for _, in := range []string{"", "no-parens", "1 (x) S", "1 (x) S 1 2"} {
		if cpu, rss := parseSelfStat(in); cpu != 0 || rss != 0 {
			t.Errorf("输入 %q 应返回 0/0，got %d/%d", in, cpu, rss)
		}
	}
}

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
		{"idle 超过 total 时钳制", 1000, 500, 1100, 900, 0},
	}
	for _, tc := range cases {
		got := cpuPercent(tc.prevTotal, tc.prevIdle, tc.curTotal, tc.curIdle)
		if got != tc.want {
			t.Errorf("%s: got %.1f, want %.1f", tc.name, got, tc.want)
		}
	}
}

func TestSelfCPUPercent(t *testing.T) {
	cases := []struct {
		name                string
		prevProc, curProc   uint64
		prevTotal, curTotal uint64
		cores               int
		want                float64
	}{
		{"2 核上占 10% 单核", 0, 50, 0, 1000, 2, 10},
		{"占满一个核", 0, 500, 0, 1000, 2, 100},
		{"占满两个核", 0, 1000, 0, 1000, 2, 200},
		{"完全空闲", 100, 100, 1000, 2000, 4, 0},
		{"系统计数器未推进", 0, 50, 1000, 1000, 2, 0},
		{"进程计数器回绕", 100, 50, 1000, 2000, 2, 0},
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

func TestParseCPUStatCountsHostCores(t *testing.T) {
	stat := strings.Join([]string{
		"cpu  100 0 100 800 0 0 0 0 50 50",
		"cpu0 50 0 50 400 0 0 0 0 50 50",
		"cpu1 50 0 50 400 0 0 0 0 0 0",
		"intr 12345 0 0",
		"ctxt 67890",
		"btime 1700000000",
		"processes 42",
		"procs_running 1",
	}, "\n")

	total, idle, cores, err := parseCPUStat(strings.NewReader(stat))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if total != 1000 {
		t.Errorf("总量错误：got %d, want 1000（guest 不得重复累加）", total)
	}
	if idle != 800 {
		t.Errorf("空闲量错误：got %d, want 800（iowait 计入空闲）", idle)
	}
	if cores != 2 {
		t.Errorf("核数错误：got %d, want 2", cores)
	}
}

func TestParseCPUStatRejectsMissingSummary(t *testing.T) {
	if _, _, _, err := parseCPUStat(strings.NewReader("intr 1\nctxt 2\n")); err == nil {
		t.Fatal("缺少 cpu 汇总行时应返回错误")
	}
	total, _, cores, err := parseCPUStat(strings.NewReader("cpu 10 0 10 80 0 0 0 0\n"))
	if err != nil || total == 0 {
		t.Fatalf("汇总行应能解析：total=%d err=%v", total, err)
	}
	if cores != runtime.NumCPU() {
		t.Errorf("无 cpuN 行时应退回 runtime.NumCPU()，got %d want %d", cores, runtime.NumCPU())
	}
}

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
