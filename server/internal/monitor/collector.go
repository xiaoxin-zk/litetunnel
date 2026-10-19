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

const (
	SampleInterval = 5 * time.Second
	MaxSamples     = 720
)

type Collector struct {
	mu      sync.RWMutex
	samples []Sample
	latest  Sample

	diskPath string

	prev     counters
	havePrev bool
	prevAt   time.Time
	prevSelf processSample
}

func New(diskPath string) *Collector {
	if strings.TrimSpace(diskPath) == "" {
		diskPath = "/"
	}
	return &Collector{
		samples:  make([]Sample, 0, MaxSamples),
		diskPath: diskPath,
	}
}

func (c *Collector) Start(ctx context.Context) {
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

func (c *Collector) Latest() Sample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

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

func (c *Collector) collect() {
	now := time.Now()

	total, idle, cores, err := readCPUCounters()
	if err != nil {
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
		CPUCores:      cores,
	}

	if mt, ma, st, sf, err := readMemInfo(); err == nil {
		s.MemTotal = mt
		s.MemAvailable = ma
		if mt > ma {
			s.MemUsed = mt - ma
		}
		s.SwapTotal = st
		if st > sf {
			s.SwapUsed = st - sf
		}
	}
	s.DiskPath = c.diskPath
	s.DiskTotal, s.DiskUsed = diskUsage(c.diskPath)

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
	prevTotal := c.prev.cpuTotal

	c.prev = counters{
		cpuTotal: total, cpuIdle: idle,
		netRx: netRx, netTx: netTx,
		diskRead: diskRead, diskWrite: diskWrite,
	}
	c.prevAt = now
	c.havePrev = true

	s.Self = c.collectSelf(prevTotal, total, cores)

	c.mu.Lock()
	c.latest = s
	if len(c.samples) >= MaxSamples {
		copy(c.samples, c.samples[1:])
		c.samples = c.samples[:len(c.samples)-1]
	}
	c.samples = append(c.samples, s)
	c.mu.Unlock()
}

func (c *Collector) collectSelf(prevTotal, curTotal uint64, cores int) *RuntimeStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	out := &RuntimeStats{
		HeapBytes:  ms.HeapAlloc,
		SysBytes:   ms.Sys,
		Goroutines: runtime.NumGoroutine(),
		GCCount:    ms.NumGC,
	}
	if ms.NumGC > 0 {
		out.GCPauseMS = float64(ms.PauseNs[(ms.NumGC-1)%256]) / 1e6
	}

	cpu, rss := readSelfStat()
	out.RSSBytes = rss
	out.CPUPercent = selfCPUPercent(c.prevSelf.cpu, cpu, prevTotal, curTotal, cores)
	c.prevSelf = processSample{cpu: cpu}
	return out
}

type processSample struct{ cpu uint64 }

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
	if max := float64(cores) * 100; p > max {
		p = max
	}
	return p
}

func readSelfStat() (cpuJiffies, rssBytes uint64) {
	raw, err := readProcSelfStat()
	if err != nil {
		return 0, 0
	}
	return parseSelfStat(raw)
}

func parseSelfStat(raw string) (cpuJiffies, rssBytes uint64) {
	closeIdx := strings.LastIndexByte(raw, ')')
	if closeIdx < 0 || closeIdx+2 >= len(raw) {
		return 0, 0
	}
	fields := strings.Fields(raw[closeIdx+2:])
	if len(fields) < 22 {
		return 0, 0
	}
	ut, _ := strconv.ParseUint(fields[11], 10, 64)
	st, _ := strconv.ParseUint(fields[12], 10, 64)
	rssPages, _ := strconv.ParseUint(fields[21], 10, 64)
	return ut + st, rssPages * uint64(syscall.Getpagesize())
}

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

func rateOf(prev, cur uint64, elapsedSeconds float64) float64 {
	if cur <= prev || elapsedSeconds <= 0 {
		return 0
	}
	return float64(cur-prev) / elapsedSeconds
}
