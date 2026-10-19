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

var errNoCPUStat = errors.New("无法从 /proc/stat 读取 CPU 统计")

type Sample struct {
	At int64 `json:"at"`

	CPUPercent float64 `json:"cpu_percent"`
	CPUCores   int     `json:"cpu_cores"`
	Load1      float64 `json:"load1"`
	Load5      float64 `json:"load5"`
	Load15     float64 `json:"load15"`

	MemTotal     uint64 `json:"mem_total"`
	MemAvailable uint64 `json:"mem_available"`
	MemUsed      uint64 `json:"mem_used"`
	SwapTotal    uint64 `json:"swap_total"`
	SwapUsed     uint64 `json:"swap_used"`

	NetRxRate  float64 `json:"net_rx_rate"`
	NetTxRate  float64 `json:"net_tx_rate"`
	NetRxTotal uint64  `json:"net_rx_total"`
	NetTxTotal uint64  `json:"net_tx_total"`

	DiskReadRate  float64 `json:"disk_read_rate"`
	DiskWriteRate float64 `json:"disk_write_rate"`

	DiskPath  string `json:"disk_path,omitempty"`
	DiskTotal uint64 `json:"disk_total"`
	DiskUsed  uint64 `json:"disk_used"`

	UptimeSeconds float64 `json:"uptime_seconds"`

	Self *RuntimeStats `json:"self,omitempty"`
}

type RuntimeStats struct {
	HeapBytes  uint64  `json:"heap_bytes"`
	RSSBytes   uint64  `json:"rss_bytes"`
	SysBytes   uint64  `json:"sys_bytes"`
	Goroutines int     `json:"goroutines"`
	GCCount    uint32  `json:"gc_count"`
	GCPauseMS  float64 `json:"gc_pause_ms"`
	CPUPercent float64 `json:"cpu_percent"`
}

type counters struct {
	cpuTotal uint64
	cpuIdle  uint64

	netRx uint64
	netTx uint64

	diskRead  uint64
	diskWrite uint64
}

func readCPUCounters() (total, idle uint64, cores int, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	return parseCPUStat(f)
}

func parseCPUStat(r io.Reader) (total, idle uint64, cores int, err error) {
	sc := bufio.NewScanner(r)
	foundTotal := false
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 3 && strings.HasPrefix(line, "cpu") && line[3] >= '0' && line[3] <= '9' {
			cores++
			continue
		}
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}

		fields := strings.Fields(line)[1:]
		for i, v := range fields {
			if i >= 8 {
				break
			}
			n, perr := strconv.ParseUint(v, 10, 64)
			if perr != nil {
				continue
			}
			total += n
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
		cores = runtime.NumCPU()
	}
	return total, idle, cores, nil
}

func readProcSelfStat() (string, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

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
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "lo" || name == "" {
			continue
		}
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
		rs, e1 := strconv.ParseUint(fields[5], 10, 64)
		ws, e2 := strconv.ParseUint(fields[9], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		read += rs * 512
		write += ws * 512
	}
	return read, write
}
