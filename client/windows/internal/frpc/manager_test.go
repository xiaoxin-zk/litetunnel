package frpc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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

func (c *collector) log(_ uint, _ string, line string) {
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
	m.SetCallbacks(c.log, func(uint, string, error) {})

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
	m.SetCallbacks(c.log, func(uint, string, error) {})

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
