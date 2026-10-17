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

	// diskPath 是磁盘容量统计所针对的路径（见 Config.MonitorDiskPath）。
	diskPath string

	// prev 是上一次的累计计数器，用于把累计值换算成速率。
	prev     counters
	havePrev bool
	prevAt   time.Time
	prevSelf processSample
}

// New 构造采集器。diskPath 为空时统计根分区。
func New(diskPath string) *Collector {
	if strings.TrimSpace(diskPath) == "" {
		diskPath = "/"
	}
	return &Collector{
		samples:  make([]Sample, 0, MaxSamples),
		diskPath: diskPath,
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
	// 磁盘容量按配置的路径统计（默认 /）。
	//
	// 容器里 / 是镜像自带的 overlay，容量既不等于宿主机根分区，也不等于
	// 数据盘；Docker 部署把面板数据挂在 /data，compose 里就把这里指到 /data。
	// 值本身仍可能不代表「宿主机」，所以 Sample 里带上路径，界面上写清楚
	// 统计的是哪块盘——比显示一个没有主语的百分比诚实。
	s.DiskPath = c.diskPath
	s.DiskTotal, s.DiskUsed = diskUsage(c.diskPath)

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
	// 进程 CPU 的分母是「同一段时间里的系统总增量」，要在 c.prev 被覆盖前取。
	prevTotal := c.prev.cpuTotal

	c.prev = counters{
		cpuTotal: total, cpuIdle: idle,
		netRx: netRx, netTx: netTx,
		diskRead: diskRead, diskWrite: diskWrite,
	}
	c.prevAt = now
	c.havePrev = true

	s.Self = c.collectSelf(prevTotal, total)

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
//
// prevTotal / curTotal 是**系统**CPU 总计数（前后两次采样），
// 用于把进程占用换算成百分比，见 selfCPUPercent。
func (c *Collector) collectSelf(prevTotal, curTotal uint64) *RuntimeStats {
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
	out.CPUPercent = selfCPUPercent(c.prevSelf.cpu, cpu, prevTotal, curTotal, runtime.NumCPU())
	c.prevSelf = processSample{cpu: cpu}
	return out
}

type processSample struct{ cpu uint64 }

// selfCPUPercent 计算面板进程自身的 CPU 占用百分比（100% = 占满一个核）。
//
// 不能沿用 cpuPercent(prevProc, 0, curProc, 0)：那是「系统使用率」的口径，
// 分母必须是同一段时间里的**系统**总增量。把空闲量填 0 进去，分母就恒等于
// 分子——进程只要用了一点 CPU 就恒等于 100%。管理页上那个长期 100% 的
// 「进程 CPU」就是这么来的。
//
// 系统总增量在 elapsed 秒内恒等于 elapsed×cores×HZ，本进程增量是消耗掉的
// jiffies；两者相除时 HZ 正好约掉，所以不需要知道 CLK_TCK——它并不总是 100，
// 写死会在某些架构上把结果整体放大或缩小。
//
// 返回值可以超过 100（多核并行时最高 cores×100），与 top 的口径一致。
func selfCPUPercent(prevProc, curProc, prevTotal, curTotal uint64, cores int) float64 {
	if cores < 1 {
		cores = 1
	}
	if curProc <= prevProc || curTotal <= prevTotal {
		return 0
	}
	deltaProc := float64(curProc - prevProc)
	deltaTotal := float64(curTotal - prevTotal)
	p := deltaProc / deltaTotal * float64(cores) * 100
	// 两个计数器都单调递增，理论上不会越界；真越界说明读数异常，
	// 钳住而不是把「800%」显示给管理员。
	if max := float64(cores) * 100; p > max {
		p = max
	}
	return p
}

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
