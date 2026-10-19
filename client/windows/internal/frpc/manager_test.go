package frpc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == "-c" {
		fmt.Println("start proxy success")
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

func TestPumpTruncatesLongLineButKeepsReading(t *testing.T) {
	m := testManager(t)

	long := strings.Repeat("x", 2<<20)
	m.pump(1, "mc1", strings.NewReader(long+"\n后面一行\n"))

	var truncated, after bool
	for _, l := range m.Logs() {
		if strings.Contains(l, "已截断") {
			truncated = true
		}
		if strings.Contains(l, "后面一行") {
			after = true
		}
		if strings.Contains(l, "日志读取中断") {
			t.Fatal("超长行不是读取故障，不该报「读取中断」")
		}
	}
	if !truncated {
		t.Fatal("超长行必须标明已截断，否则用户以为日志是完整的")
	}
	if !after {
		t.Fatal("超长行之后的内容必须继续被读取：停读会让子进程阻塞在写管道上，永远退不出去")
	}
}

func TestPumpReportsReadError(t *testing.T) {
	m := testManager(t)

	m.pump(1, "mc1", iotest.ErrReader(errors.New("管道已断开")))

	var found bool
	for _, l := range m.Logs() {
		if strings.Contains(l, "日志读取中断") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("读取失败必须留下痕迹，实际日志: %v", m.Logs())
	}
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("取测试二进制路径失败: %v", err)
	}
	return New(exe)
}

func testConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frpc.toml")
	if err := os.WriteFile(path, []byte("serverAddr = \"127.0.0.1\"\n"), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	return path
}

type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) log(_ uint, _ string, _ uint64, line string) {
	c.mu.Lock()
	c.lines = append(c.lines, line)
	c.mu.Unlock()
}

func (c *collector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

func (c *collector) waitForLine(t *testing.T, prefix, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range c.snapshot() {
			if strings.Contains(l, prefix) && strings.Contains(l, want) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待日志超时：期望带 %s 前缀且包含 %q 的行，实际日志: %v", prefix, want, c.snapshot())
}

func TestTunnelProcessesAreIndependent(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)

	c := &collector{}
	m.SetCallbacks(c.log, func(uint, string, error, bool) {})

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("启动隧道 1 失败: %v", err)
	}
	if err := m.Start(2, "nas", cfg); err != nil {
		t.Fatalf("启动隧道 2 失败: %v", err)
	}
	if !m.Running(1) || !m.Running(2) {
		t.Fatal("两条隧道都应处于运行中")
	}
	if err := m.Start(1, "mc1", cfg); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("重复启动应返回 ErrAlreadyRunning，实际: %v", err)
	}

	c.waitForLine(t, "Tunnel/mc1", "start proxy success")
	c.waitForLine(t, "Tunnel/nas", "start proxy success")

	if got := m.TunnelName(1); got != "mc1" {
		t.Fatalf("TunnelName(1) = %q，期望 mc1", got)
	}

	if err := m.Stop(1); err != nil {
		t.Fatalf("停止隧道 1 失败: %v", err)
	}
	if m.Running(1) {
		t.Fatal("隧道 1 应已停止")
	}
	if !m.Running(2) {
		t.Fatal("停掉隧道 1 不应影响隧道 2")
	}
	if got := m.TunnelName(1); got != "" {
		t.Fatalf("已停止的隧道不应还记着名字: %q", got)
	}

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("重新启动隧道 1 失败: %v", err)
	}

	if err := m.StopAll(); err != nil {
		t.Fatalf("停止全部失败: %v", err)
	}
	if m.AnyRunning() {
		t.Fatal("StopAll 之后不应还有进程在跑")
	}
	if ids := m.RunningIDs(); len(ids) != 0 {
		t.Fatalf("StopAll 之后仍有运行中的隧道: %v", ids)
	}
}

func TestLogLinesCarryTunnelPrefix(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)

	c := &collector{}
	m.SetCallbacks(c.log, func(uint, string, error, bool) {})

	if err := m.Start(7, "mc1", cfg); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer func() { _ = m.StopAll() }()

	c.waitForLine(t, "Tunnel/mc1", "start proxy success")

	for _, l := range c.snapshot() {
		if !strings.Contains(l, "Tunnel/mc1") {
			t.Fatalf("日志行缺少隧道前缀: %q", l)
		}
	}
}

func TestLogBufferRespectsByteBudget(t *testing.T) {
	m := testManager(t)
	for i := 0; i < 200; i++ {
		m.appendLog(1, "mc1", fmt.Sprintf("%d-%s", i, strings.Repeat("x", maxLogLineBytes)))
	}

	m.mu.Lock()
	bytes, lines := m.logBytes, len(m.logs)
	sum := 0
	for _, l := range m.logs {
		sum += len(l.Text)
	}
	m.mu.Unlock()

	if lines > maxLogLines {
		t.Fatalf("行数必须有界：实际 %d 行（上限 %d）", lines, maxLogLines)
	}
	if bytes > maxLogBytes {
		t.Fatalf("日志总字节必须有界：实际 %d（上限 %d）", bytes, maxLogBytes)
	}
	if bytes != sum {
		t.Fatalf("字节计数必须与日志内容一致：计数 %d，实际 %d", bytes, sum)
	}

	m2 := testManager(t)
	m2.appendLog(1, "mc1", strings.Repeat("y", 4*maxLogLineBytes))
	logs := m2.Logs()
	if len(logs) != 1 {
		t.Fatalf("应只留一行，实际 %d 行", len(logs))
	}
	if len(logs[0]) > maxLogLineBytes+64 {
		t.Fatalf("单行必须被截断：实际 %d 字节", len(logs[0]))
	}
	if !strings.Contains(logs[0], "已截断") {
		t.Fatal("截断后应标明，否则用户以为日志完整")
	}
}

func TestLogMergesRepeatedLines(t *testing.T) {
	m := testManager(t)

	for i := 0; i < 50; i++ {
		m.appendLog(1, "mc", "connect to local service error")
	}
	if got := m.Logs(); len(got) != 1 {
		t.Fatalf("连续重复行应合并为一条，实际 %d 条", len(got))
	}

	m.appendLog(1, "mc", "start proxy success")
	got := m.Logs()
	if len(got) != 3 {
		t.Fatalf("换行后应先补一条计数、再记新行，实际 %d 条: %v", len(got), got)
	}
	if !strings.Contains(got[1], "重复 49 次") {
		t.Fatalf("应交代被合并的次数，实际 %q", got[1])
	}
	if !strings.Contains(got[2], "start proxy success") {
		t.Fatalf("新行必须保留，实际 %q", got[2])
	}
}

func TestLogCallbackSeesMonotonicSeq(t *testing.T) {
	m := testManager(t)

	var mu sync.Mutex
	var seqs []uint64
	m.SetCallbacks(func(_ uint, _ string, seq uint64, _ string) {
		mu.Lock()
		seqs = append(seqs, seq)
		mu.Unlock()
	}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				m.appendLog(uint(id), fmt.Sprintf("t%d", id), fmt.Sprintf("line-%d-%d", id, j))
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seqs)
		mu.Unlock()
		if n >= 400 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != 400 {
		t.Fatalf("应投递 400 行，实际 %d", len(seqs))
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("投递顺序必须与序号一致，第 %d 项 %d <= 前一项 %d", i, seqs[i], seqs[i-1])
		}
	}
}

func TestLogCallbackCanReenterManager(t *testing.T) {
	m := testManager(t)
	m.SetCallbacks(func(_ uint, _ string, _ uint64, line string) {
		if strings.Contains(line, "start proxy success") {
			m.AppendRaw("15:04:05  Tunnel/mc  隧道启动成功")
		}
	}, nil)

	m.appendLog(1, "mc", "start proxy success")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		logs := m.Logs()
		if len(logs) >= 2 && strings.Contains(logs[1], "隧道启动成功") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("回调重入 Manager 后未能写入日志（可能已死锁）")
}

func TestAppendRawSharesHistoryAndSeq(t *testing.T) {
	m := testManager(t)
	var (
		mu   sync.Mutex
		seqs []uint64
	)
	m.SetCallbacks(func(_ uint, _ string, seq uint64, _ string) {
		mu.Lock()
		seqs = append(seqs, seq)
		mu.Unlock()
	}, nil)

	m.appendLog(1, "mc", "frpc line")
	m.AppendRaw("15:04:05  启动同步完成")

	logs := m.Logs()
	if len(logs) != 2 {
		t.Fatalf("客户端说明应进入同一份历史，实际 %d 条: %v", len(logs), logs)
	}
	if !strings.Contains(logs[1], "启动同步完成") {
		t.Fatalf("客户端说明缺失: %v", logs)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seqs)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != 2 || seqs[1] <= seqs[0] {
		t.Fatalf("序号必须单调递增，实际 %v", seqs)
	}
}

func TestClearLogsResetsRepeatState(t *testing.T) {
	m := testManager(t)
	m.appendLog(1, "mc", "same line")
	m.ClearLogs()
	m.appendLog(1, "mc", "same line")
	if got := m.Logs(); len(got) != 1 {
		t.Fatalf("清空后的第一条日志不能被合并掉，实际 %d 条: %v", len(got), got)
	}
}

func TestCloseRejectsNewProcess(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if m.AnyRunning() {
		t.Fatal("Close 之后不应还有进程在跑")
	}
	if !m.Closed() {
		t.Fatal("Close 之后应处于关闭状态")
	}
	if err := m.Start(1, "mc1", cfg); !errors.Is(err, ErrClosed) {
		t.Fatalf("关闭后再启动应返回 ErrClosed，实际: %v", err)
	}
	if err := m.Start(2, "nas", cfg); !errors.Is(err, ErrClosed) {
		t.Fatalf("关闭后启动其他隧道也应返回 ErrClosed，实际: %v", err)
	}
}

func TestStaleExitCallbackDoesNotOverrideNewProcess(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)
	t.Cleanup(func() { _ = m.Close() })

	var (
		mu    sync.Mutex
		stale bool
	)
	m.SetCallbacks(nil, func(id uint, _ string, _ error, _ bool) {
		if m.Running(id) {
			mu.Lock()
			stale = true
			mu.Unlock()
		}
	})

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := m.Stop(1); err != nil {
			t.Fatalf("第 %d 次停止失败: %v", i, err)
		}
		if err := m.Start(1, "mc1", cfg); err != nil {
			t.Fatalf("第 %d 次重启失败: %v", i, err)
		}
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		bad := stale
		mu.Unlock()
		if bad {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if stale {
		t.Fatal("旧进程的退出回调在新进程运行后仍被执行，会把刚连上的隧道标成未连接")
	}
}

func TestStartRejectsMissingConfig(t *testing.T) {
	m := testManager(t)

	err := m.Start(1, "mc1", filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatal("配置不存在时应报错")
	}
	if m.Running(1) {
		t.Fatal("启动失败后不应留下运行记录")
	}
}

func TestWaitCallbacksCoversStopAllReturn(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)
	t.Cleanup(func() { _ = m.Close() })

	var (
		mu     sync.Mutex
		inExit int
		landed int
	)
	m.SetCallbacks(nil, func(uint, string, error, bool) {
		mu.Lock()
		inExit++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		inExit--
		landed++
		mu.Unlock()
	})

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if err := m.StopAll(); err != nil {
		t.Fatalf("停止全部失败: %v", err)
	}

	if !m.WaitCallbacks(5 * time.Second) {
		t.Fatal("StopAll 返回后必须能等到在途的退出回调，否则登出会先清凭据再被回调改状态")
	}
	mu.Lock()
	defer mu.Unlock()
	if landed != 1 {
		t.Fatalf("退出回调应当恰好执行一次，实际 %d 次", landed)
	}
	if inExit != 0 {
		t.Fatalf("WaitCallbacks 返回时不应还有回调在执行，实际 %d 个", inExit)
	}
}

func TestWaitCallbacksReturnsFalseOnTimeout(t *testing.T) {
	m := testManager(t)
	cfg := testConfig(t)
	t.Cleanup(func() { _ = m.Close() })

	block := make(chan struct{})
	exited := make(chan struct{}, 1)
	m.SetCallbacks(nil, func(uint, string, error, bool) {
		<-block
		exited <- struct{}{}
	})

	if err := m.Start(1, "mc1", cfg); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if err := m.StopAll(); err != nil {
		t.Fatalf("停止全部失败: %v", err)
	}

	start := time.Now()
	ok := m.WaitCallbacks(100 * time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Fatal("回调仍卡着时不该报告「已全部落地」")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("等待必须有上限，实际等了 %s", elapsed.Round(time.Millisecond))
	}
	close(block)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("回调未被放行")
	}
}
