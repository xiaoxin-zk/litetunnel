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

// TestMain 让测试二进制自己扮演 frpc。
//
// Manager 的价值几乎全在「真的起一个进程、读它的输出、按隧道记账、
// 把它杀掉」这几件事上，把 exec 换成 mock 就等于什么都没测。
// 所以这里用测试二进制冒充 frpc：Manager 以 `frpc -c <配置>` 的方式
// 拉起它，它打印一行 frpc 启动成功时会打印的内容，然后一直挂着，
// 直到被父进程杀掉。
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == "-c" {
		fmt.Println("start proxy success")
		// 不能写 select{}：整个程序只剩这一个被阻塞的协程时，
		// Go 运行时会判定死锁并直接 panic。
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

// TestPumpTruncatesLongLineButKeepsReading 覆盖「超长单行不得让读取端停摆」。
//
// 旧实现用 bufio.Scanner：超过 1 MiB 的行会让它返回 ErrTooLong 并**停止
// 读取**，管道再没人消费，写端一满子进程就阻塞在写日志上——它既不退出
// 也不响应，cmd.Wait 永远不返回，界面一直把这条隧道显示成「运行中」。
// 现在超限只截断日志内容，读取继续到换行、继续跟进后面的行。
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

// TestPumpReportsReadError 覆盖「读取端真的坏了」时留痕。
//
// 这种情况与超长行不同：管道本身出错，读取确实无法继续，必须写一行日志，
// 否则日志会凭空停在某一行，看起来像「frpc 不再输出了」。
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

// collector 收集回调推来的日志行，供断言使用。
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

// waitForLine 等一行同时包含前缀与关键词的日志出现。
//
// 子进程的输出是异步到达的，不能用「启动后立刻断言」的方式测——
// 那会变成一条在快机器上偶发通过的测试。
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

// TestTunnelProcessesAreIndependent 是这套实现的核心不变式。
//
// 曾经的实现是一个进程承载全部隧道：任何一条隧道的改动都要重启整个进程，
// 其他隧道跟着断一下。这条测试守的就是「不再如此」。
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
	// 同一条隧道不能有两个进程：那会让「关掉一条」变成关不干净。
	if err := m.Start(1, "mc1", cfg); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("重复启动应返回 ErrAlreadyRunning，实际: %v", err)
	}

	c.waitForLine(t, "Tunnel/mc1", "start proxy success")
	c.waitForLine(t, "Tunnel/nas", "start proxy success")

	// 名字要在运行期间取得到：隧道在服务端被删掉后，客户端只剩一个 ID，
	// 「正在断开」这条日志的前缀得靠它还原。
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

	// Stop 必须等到进程真的消失才返回。否则紧接着的 Start 会撞上
	// ErrAlreadyRunning，表现为「关掉再打开就打不开了」——
	// 这正是旧实现里「自动同步把 frpc 停掉却起不来」的根因。
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

// TestLogLinesCarryTunnelPrefix 保证日志能按隧道分开看。
//
// 每条隧道一个进程之后，日志区是多个进程的输出交织在一起，
// 没有前缀就完全读不出「哪条隧道出了什么问题」。
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

// TestLogBufferRespectsByteBudget 覆盖「只限行数挡不住超大日志」。
//
// 单行可以留到 1 MiB，500 行就是 500 MiB——而日志洪峰恰恰出现在客户端出
// 问题的时候。现在按总字节再裁一次，并把单行压到 maxLogLineBytes。
func TestLogBufferRespectsByteBudget(t *testing.T) {
	m := testManager(t)
	// 每行加不同前缀：完全相同的连续行会被合并（见重复行合并），
	// 那样测不到字节预算这条路径。
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

	// 单行超长：截断后仍要留下，且标明截断。
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

// TestLogMergesRepeatedLines 覆盖「同一条错误刷屏把日志挤满」。
//
// 本地服务没起来时，frpc 会为每一次连接失败打一行完全相同的错误；
// 被扫描或 tcping 时一秒能刷几百行，500 行的缓冲几秒就被同一条占满，
// 之前真正有用的日志全被挤掉。
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

// TestLogCallbackSeesMonotonicSeq 覆盖并发输出时的乱序投递。
//
// 回调原先在解锁之后执行：两条隧道同时输出时，序号大的可能先被投递，
// 调用方按序号去重就会把随后迟到的较小序号当成重复丢掉。
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

// TestAppendRawSharesHistoryAndSeq 覆盖「客户端自身日志不进历史」。
//
// 两条来源必须落进同一份缓冲、共用同一个序号：否则重新加载日志时
// 客户端说明会消失，而且实时显示的顺序与快照顺序可能不一致。
func TestAppendRawSharesHistoryAndSeq(t *testing.T) {
	m := testManager(t)
	var seqs []uint64
	m.SetCallbacks(func(_ uint, _ string, seq uint64, _ string) {
		seqs = append(seqs, seq)
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
	if len(seqs) != 2 || seqs[1] <= seqs[0] {
		t.Fatalf("序号必须单调递增，实际 %v", seqs)
	}
}

// TestClearLogsResetsRepeatState 覆盖「清空后第一条日志被当成重复吞掉」。
func TestClearLogsResetsRepeatState(t *testing.T) {
	m := testManager(t)
	m.appendLog(1, "mc", "same line")
	m.ClearLogs()
	m.appendLog(1, "mc", "same line")
	if got := m.Logs(); len(got) != 1 {
		t.Fatalf("清空后的第一条日志不能被合并掉，实际 %d 条: %v", len(got), got)
	}
}

// TestCloseRejectsNewProcess 覆盖「关停之后不再拉起新进程」。
//
// 关闸必须发生在停进程之前：只调 StopAll 的话，与退出并发的一轮同步
// 可以在 StopAll 之后拿到配置再起一个进程，那个进程就没人管了。
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

// TestStartRejectsMissingConfig 覆盖「配置没写好就起进程」这条错误路径：
// 不拦的话 frpc 会带着一个不存在的配置启动并立刻失败，
// 用户只看到「隧道起来了又断」，原因却在日志最前面几行。
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
