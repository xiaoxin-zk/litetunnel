// Package monitor 采集宿主机与面板自身的运行指标。
//
// # 为什么直接读 /proc 而不用 gopsutil
//
// gopsutil 是 Go 生态里的事实标准，但它的核心价值是**跨平台抽象**
// （Linux / macOS / Windows / BSD 各一套实现）。而本面板只以 Linux 容器
// 形态运行——那份抽象我们一行都用不上，却要引入一整棵依赖树。
//
// 更关键的是仓库里已有同样的先例：firewall/scan.go 读 /proc/net/* 扫监听
// 端口，理由完全相同——容器镜像里不保证装了 iproute2 / net-tools，
// 而 /proc 在任何 Linux 上都存在且读取不需要特权。
//
// 这里需要的数值都是稳定了几十年的计数器（/proc/stat、/proc/meminfo、
// /proc/net/dev、/proc/diskstats），语义没有版本差异。
//
// # 容器里读到的是什么
//
// procfs 只对「进程」与「网络」命名空间敏感：
//
//   - /proc/stat、/proc/meminfo、/proc/loadavg、/proc/diskstats
//     → **宿主机**全局数据（不受容器限制）
//   - /proc/net/dev → 与 network_mode: host 一致，即宿主机网卡
//
// 也就是说这里拿到的是「服务器」的指标，而不是容器被 cgroup 限制后的
// 视角——这正是管理员在「系统概览」里想看的。
//
// 面板**自身**的消耗（Go 堆、协程数）单独采集，见 RuntimeStats。
package monitor

import (
	"bufio"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// errNoCPUStat 表示 /proc/stat 里找不到 `cpu` 汇总行。
// 正常情况下不会出现——除非不在 Linux 上跑，或 /proc 没挂载。
var errNoCPUStat = errors.New("无法从 /proc/stat 读取 CPU 统计")

// Sample 是一次系统指标采样。
//
// 所有速率字段（*_rate）都是**相对上一次采样的增量换算**，
// 而不是累计值——累计值无法直接反映「现在忙不忙」。
type Sample struct {
	At int64 `json:"at"` // Unix 毫秒

	// ---- CPU ----
	CPUPercent float64 `json:"cpu_percent"` // 0-100，所有核心的平均占用
	CPUCores   int     `json:"cpu_cores"`
	Load1      float64 `json:"load1"`
	Load5      float64 `json:"load5"`
	Load15     float64 `json:"load15"`

	// ---- 内存 ----
	MemTotal     uint64 `json:"mem_total"`
	MemAvailable uint64 `json:"mem_available"`
	MemUsed      uint64 `json:"mem_used"`
	SwapTotal    uint64 `json:"swap_total"`
	SwapUsed     uint64 `json:"swap_used"`

	// ---- 网络（字节/秒，全部物理网卡合计，不含 lo）----
	NetRxRate  float64 `json:"net_rx_rate"`
	NetTxRate  float64 `json:"net_tx_rate"`
	NetRxTotal uint64  `json:"net_rx_total"`
	NetTxTotal uint64  `json:"net_tx_total"`

	// ---- 磁盘 IO（字节/秒）----
	DiskReadRate  float64 `json:"disk_read_rate"`
	DiskWriteRate float64 `json:"disk_write_rate"`

	// ---- 磁盘容量 ----
	//
	// DiskPath 是统计所针对的挂载点（LT_MONITOR_DISK_PATH，默认 /）。
	// 必须一起返回：容器里 / 是镜像的 overlay，/data 才是挂出来的数据盘，
	// 只给一个百分比等于没说清「这是哪块盘」。
	DiskPath  string `json:"disk_path,omitempty"`
	DiskTotal uint64 `json:"disk_total"`
	DiskUsed  uint64 `json:"disk_used"`

	// ---- 其他 ----
	UptimeSeconds float64 `json:"uptime_seconds"`

	// ---- 面板自身 ----
	// 单独采集，用于判断「面板是不是自己把机器吃满了」。
	Self *RuntimeStats `json:"self,omitempty"`
}

// RuntimeStats 是 Go 进程自身的运行时指标。
//
// 这些数据只有 Go 能精确提供（堆分配、GC、协程数），
// 从 /proc 读不到——而排查「面板自己内存涨了」时它们最有用。
type RuntimeStats struct {
	HeapBytes  uint64  `json:"heap_bytes"` // 当前堆占用
	RSSBytes   uint64  `json:"rss_bytes"`  // 常驻内存（含非堆部分）
	SysBytes   uint64  `json:"sys_bytes"`  // 向操作系统申请的总量
	Goroutines int     `json:"goroutines"`
	GCCount    uint32  `json:"gc_count"`
	GCPauseMS  float64 `json:"gc_pause_ms"` // 最近一次 GC 停顿
	CPUPercent float64 `json:"cpu_percent"` // 进程自身 CPU 占用
}

// counters 是从 /proc 读到的**累计计数器**原始值。
//
// 它们本身没有意义，必须与上一次采样相减才能得到速率。
// 单独用一个结构体承载，是为了让「累计值 → 速率」这一步集中在一处，
// 而不是散落在各个解析函数里。
type counters struct {
	cpuTotal uint64
	cpuIdle  uint64

	netRx uint64
	netTx uint64

	diskRead  uint64
	diskWrite uint64
}

// readCPUCounters 解析 /proc/stat，返回汇总计数与**宿主机**核数。
func readCPUCounters() (total, idle uint64, cores int, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	return parseCPUStat(f)
}

// parseCPUStat 从 /proc/stat 的内容里取汇总计数与核数。
//
// 各字段含义（顺序固定，内核从未变更）：
//
//	user nice system idle iowait irq softirq steal guest guest_nice
//
// 注意 guest / guest_nice 已包含在 user / nice 里，**不能重复累加**，
// 否则总量偏大、使用率偏低。这是实现里最常见的错误。
//
// 核数取自 cpuN 行的**个数**，而不是 runtime.NumCPU()：
//
//   - 上面的 cpu 汇总行是**宿主机**口径（procfs 只对进程与网络命名空间敏感，
//     CPU 计数不受 cgroup 限制）；
//   - runtime.NumCPU() 返回的是本进程**可用**核数，容器设了 cpuset / CPU
//     affinity 时会少于宿主机核数。
//
// 两者混用会让进程 CPU 的分母凭空变大或变小（显示偏低），也会让管理页拿
// 错误的核数去判断宿主机负载（过早标红）。分子分母必须同源。
//
// 抽成接受 io.Reader 的纯函数是为了可测：cpuset 生效时的输出与宿主机不同，
// 只有能喂固定输入才验证得了「按 cpuN 行数」这件事。
func parseCPUStat(r io.Reader) (total, idle uint64, cores int, err error) {
	sc := bufio.NewScanner(r)
	foundTotal := false
	for sc.Scan() {
		line := sc.Text()
		// cpuN（每个逻辑 CPU 一行）先判：它们与 "cpu " 汇总行的前缀只差空格。
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			cores++
			continue
		}
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}

		fields := strings.Fields(line)[1:] // 去掉 "cpu"
		for i, v := range fields {
			// 只取前 8 个字段（user..steal）。
			// guest 与 guest_nice 已计入 user 与 nice，重复累加会让
			// 使用率算出来偏低。
			if i >= 8 {
				break
			}
			n, perr := strconv.ParseUint(v, 10, 64)
			if perr != nil {
				continue
			}
			total += n
			// 第 4 个（索引 3）是 idle，第 5 个（索引 4）是 iowait。
			// iowait 期间 CPU 实际是空闲的，必须算进 idle，
			// 否则磁盘等待会被误报成 CPU 繁忙。
			if i == 3 || i == 4 {
				idle += n
			}
		}
		foundTotal = true
	}
	if err := sc.Err(); err != nil {
		return 0, 0, 0, err
	}
	if !foundTotal {
		return 0, 0, 0, errNoCPUStat
	}
	if cores == 0 {
		// 理论上 cpu 汇总行必定伴随 cpuN 行；真没有时退回运行时值，
		// 总比显示 0 核好（那样负载阈值会永远标红）。
		cores = runtime.NumCPU()
	}
	return total, idle, cores, nil
}

// readProcSelfStat 读取本进程的 /proc/self/stat 原始内容。
//
// 单独抽出来是为了让调用方能在测试里替换数据源（见 collector_test.go），
// 否则解析逻辑只能靠真实进程状态验证，而真实值每次都不同。
func readProcSelfStat() (string, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// readNetCounters 汇总 /proc/net/dev 中所有物理网卡的收发字节数。
//
// 排除 lo：回环流量不代表真实网络负载，把它算进来会让
// 「面板自己访问 frps 管理接口」这类内部通信显示成外网流量。
func readNetCounters() (rx, tx uint64, err error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue // 前两行是表头
		}
		name := strings.TrimSpace(line[:i])
		if name == "lo" || name == "" {
			continue
		}
		// 格式：face: rx_bytes rx_packets ... tx_bytes ...
		// 收发各 8 个字段，rx_bytes 是第 1 个，tx_bytes 是第 9 个。
		fields := strings.Fields(line[i+1:])
		if len(fields) < 9 {
			continue
		}
		r, e1 := strconv.ParseUint(fields[0], 10, 64)
		t, e2 := strconv.ParseUint(fields[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		rx += r
		tx += t
	}
	return rx, tx, nil
}

// readMemInfo 读取 /proc/meminfo 中关心的几项（单位为 KB）。
func readMemInfo() (total, available, swapTotal, swapFree uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, perr := strconv.ParseUint(fields[1], 10, 64)
		if perr != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = v * 1024
		case "MemAvailable":
			available = v * 1024
		case "SwapTotal":
			swapTotal = v * 1024
		case "SwapFree":
			swapFree = v * 1024
		}
	}
	return total, available, swapTotal, swapFree, nil
}

// readLoadAvg 读取 /proc/loadavg 的 1 / 5 / 15 分钟负载。
func readLoadAvg() (l1, l5, l15 float64) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	l1, _ = strconv.ParseFloat(fields[0], 64)
	l5, _ = strconv.ParseFloat(fields[1], 64)
	l15, _ = strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15
}

// readUptime 读取 /proc/uptime 的秒数。
func readUptime() float64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// physicalDisks 列出物理块设备名。
//
// 用 /sys/block 而不是直接遍历 /proc/diskstats：
// 后者同时包含分区（sda1、nvme0n1p1）与伪设备，
// 逐个累加会把同一份 IO 统计两遍（整盘 + 分区），数值直接翻倍。
//
// /sys/block 只列整盘，天然避开这个问题。再排除 loop / ram / zram，
// 它们不是真实磁盘 IO。
func physicalDisks() []string {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") ||
			strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "zram") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// readDiskCounters 汇总物理磁盘的读写字节数。
//
// /proc/diskstats 的字段顺序（内核文档 Documentation/admin-guide/iostats.rst）：
//
//	major minor name reads_completed reads_merged sectors_read ms_reading
//	writes_completed writes_merged sectors_written ...
//
// sectors 始终按 **512 字节** 计算，与磁盘的实际扇区大小无关——
// 这是个固定的换算约定，用 4096 会算错 8 倍。
func readDiskCounters() (read, write uint64) {
	disks := physicalDisks()
	if len(disks) == 0 {
		return 0, 0
	}
	want := make(map[string]bool, len(disks))
	for _, d := range disks {
		want[d] = true
	}

	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if !want[fields[2]] {
			continue
		}
		rs, e1 := strconv.ParseUint(fields[5], 10, 64) // sectors_read
		ws, e2 := strconv.ParseUint(fields[9], 10, 64) // sectors_written
		if e1 != nil || e2 != nil {
			continue
		}
		read += rs * 512
		write += ws * 512
	}
	return read, write
}
