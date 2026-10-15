package monitor

import (
	"context"
	"log"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 采样与保留参数。
//
// 这两个值共同决定内存占用，是刻意选的：
//
//	5 秒 × 720 点 = 最近 1 小时，约 200 KB
//
// 环形缓冲**天然有界**，这是刻意的选择：1Panel 的运维监控曾因为数据量
// 无限增长而拖慢面板本身（官方论坛专门发过清理工具）。时间序列最容易
// 变成「不修就会在某天出事」的组件，所以这里从第一天起就不落库、不增长。
const (
	SampleInterval = 5 * time.Second
	MaxSamples     = 720
)

// Collector 采集指标并维护历史序列。
type Collector struct {
	mu      sync.RWMutex
	samples []Sample // 环形缓冲，长度不超过 MaxSamples
	latest  Sample

	// prev 是上一次的累计计数器，用于把累计值换算成速率。
	prev      counters
	havePrev  bool
	prevAt    time.Time
	prevSelf  processSample
	prevSelfAt time.Time
}

// New 构造采集器。
func New() *Collector {
	return &Collector{
		samples: make([]Sample, 0, MaxSamples),
	}
}

// Start 启动后台采样协程，直到 ctx 结束。
func (c *Collector) Start(ctx context.Context) {
	// 先立即采一次：否则面板刚启动的几秒内页面上全是 0，
	// 管理员会以为监控坏了。
	c.collect()

	ticker := time.NewTicker(SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

// Latest 返回最近一次采样。
func (c *Collector) Latest() Sample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

// Series 返回最多 limit 条历史采样（按时间正序）。
//
// when 为 0 时返回全部。limit 会被夹到 MaxSamples 以内。
func (c *Collector) Series(limit int) []Sample {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 || limit > len(c.samples) {
		limit = len(c.samples)
	}
	start := len(c.samples) - limit
	out := make([]Sample, limit)
	copy(out, c.samples[start:])
	return out
}

// collect 执行一次采样并写入环形缓冲。
func (c *Collector) collect() {
	now := time.Now()

	total, idle, err := readCPUCounters()
	if err != nil {
		// 读不到就保持上一次的值，不把 0 写进序列——
		// 序列里的假 0 会让图表出现莫名其妙的凹陷，比空缺更误导人。
		log.Printf("[monitor] 读取 CPU 统计失败: %v", err)
		return
	}
	netRx, netTx, _ := readNetCounters()
	diskRead, diskWrite := readDiskCounters()

	l1, l5, l15 := readLoadAvg()
	s := Sample{
		At:            now.UnixMilli(),
		Load1:         l1,
		Load5:         l5,
		Load15:        l15,
		UptimeSeconds: readUptime(),
		NetRxTotal:    netRx,
		NetTxTotal:    netTx,
		CPUCores:      runtime.NumCPU(),
	}

	if mt, ma, st, sf, err := readMemInfo(); err == nil {
		s.MemTotal = mt
		s.MemAvailable = ma
		// 已用 = 总量 - 可用。
		//
		// 不用「总量 - 空闲」：那会把可回收的页缓存算成已用，
		// 在跑了一阵的机器上会稳定显示 90%+，看起来像随时要 OOM。
		// MemAvailable 是内核给出的「不触发交换的情况下可分配量」，
		// 才是正确的口径。
		if mt > ma {
			s.MemUsed = mt - ma
		}
		s.SwapTotal = st
		if st > sf {
			s.SwapUsed = st - sf
		}
	}
	s.DiskTotal, s.DiskUsed = diskUsage("/")

	// 速率：由累计计数器求差。首次采样没有基线，速率留 0。
	if c.havePrev {
		elapsed := now.Sub(c.prevAt).Seconds()
		if elapsed > 0 {
			s.CPUPercent = cpuPercent(c.prev.cpuTotal, c.prev.cpuIdle, total, idle)
			s.NetRxRate = rateOf(c.prev.netRx, netRx, elapsed)
			s.NetTxRate = rateOf(c.prev.netTx, netTx, elapsed)
			s.DiskReadRate = rateOf(c.prev.diskRead, diskRead, elapsed)
			s.DiskWriteRate = rateOf(c.prev.diskWrite, diskWrite, elapsed)
		}
	}
	c.prev = counters{
		cpuTotal: total, cpuIdle: idle,
		netRx: netRx, netTx: netTx,
		diskRead: diskRead, diskWrite: diskWrite,
	}
	c.prevAt = now
	c.havePrev = true

	s.Self = c.collectSelf(now)

	c.mu.Lock()
	c.latest = s
	if len(c.samples) >= MaxSamples {
		// 环形推进：丢掉最旧的一条。
		copy(c.samples, c.samples[1:])
		c.samples = c.samples[:len(c.samples)-1]
	}
	c.samples = append(c.samples, s)
	c.mu.Unlock()
}

// collectSelf 采集面板进程自身的运行时指标。
func (c *Collector) collectSelf(now time.Time) *RuntimeStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	out := &RuntimeStats{
		HeapBytes:  ms.HeapAlloc,
		SysBytes:   ms.Sys,
		Goroutines: runtime.NumGoroutine(),
		GCCount:    ms.NumGC,
	}
	if ms.NumGC > 0 {
		// 取最近一次 GC 的停顿时间。ms.PauseNs 是环形数组，
		// 下标 (NumGC-1) % 256 指向最近一次。
		out.GCPauseMS = float64(ms.PauseNs[(ms.NumGC-1)%256]) / 1e6
	}

	// RSS 与进程 CPU 只能从 /proc 拿：Go 的 MemStats 不包含
	// 由 C 分配或被内核计入的非堆内存，而这个差值恰恰是
	// 排查「面板内存涨了」时最需要看的。
	cpu, rss := readSelfStat()
	out.RSSBytes = rss
	if c.prevSelfAt.IsZero() {
		out.CPUPercent = 0
	} else {
		elapsed := now.Sub(c.prevSelfAt).Seconds()
		if elapsed > 0 {
			out.CPUPercent = cpuPercent(c.prevSelf.cpu, 0, cpu, 0)
		}
	}
	c.prevSelf = processSample{cpu: cpu}
	c.prevSelfAt = now
	return out
}

type processSample struct{ cpu uint64 }

// readSelfStat 读取本进程的 CPU 时间（jiffies）与常驻内存（字节）。
//
// /proc/self/stat 的第 14、15 项是 utime 与 stime。
//
// 注意：不能简单用 strings.Fields 切分——第 2 项 comm 是进程名，
// 它被括号包裹且**可能包含空格**（Go 编译出的二进制名通常不含，
// 但一旦含了，后续所有字段的下标都会错位）。所以先从最后一个
// ')' 之后开始切。
func readSelfStat() (cpuJiffies, rssBytes uint64) {
	raw, err := readProcSelfStat()
	if err != nil {
		return 0, 0
	}
	return parseSelfStat(raw)
}

// parseSelfStat 解析 /proc/self/stat，返回 CPU 时间与常驻内存。
//
// 抽成纯函数是为了可测：真实进程的这两个值每次都不同，
// 只有能喂固定输入才能验证解析是否正确。
func parseSelfStat(raw string) (cpuJiffies, rssBytes uint64) {
	// 先跳过 comm 字段：它被括号包裹且**可能包含空格**，
	// 直接用 strings.Fields 切分会让其后的字段全部错位。
	closeIdx := strings.LastIndexByte(raw, ')')
	if closeIdx < 0 || closeIdx+2 >= len(raw) {
		return 0, 0
	}
	fields := strings.Fields(raw[closeIdx+2:])
	// 从 comm 之后重新计数（state 为第 1 项）：
	//   utime=12  stime=13  rss=22
	if len(fields) < 22 {
		return 0, 0
	}
	ut, _ := strconv.ParseUint(fields[11], 10, 64)
	st, _ := strconv.ParseUint(fields[12], 10, 64)
	rssPages, _ := strconv.ParseUint(fields[21], 10, 64)
	return ut + st, rssPages * uint64(syscall.Getpagesize())
}

// cpuPercent 由两次累计值算使用率（0-100）。
func cpuPercent(prevTotal, prevIdle, curTotal, curIdle uint64) float64 {
	if curTotal <= prevTotal {
		return 0
	}
	dt := float64(curTotal - prevTotal)
	di := float64(0)
	if curIdle > prevIdle {
		di = float64(curIdle - prevIdle)
	}
	if di > dt {
		di = dt
	}
	p := (dt - di) / dt * 100
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// rateOf 由两个累计值算每秒增量。
//
// 计数器回绕（重启网卡、重启容器）时当前值会小于上一次，
// 此时返回 0 而不是一个巨大的负数——负速率在图表上会画成向下的尖刺，
// 让管理员以为出了故障。
func rateOf(prev, cur uint64, elapsedSeconds float64) float64 {
	if cur <= prev || elapsedSeconds <= 0 {
		return 0
	}
	return float64(cur-prev) / elapsedSeconds
}


