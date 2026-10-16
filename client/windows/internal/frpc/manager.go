// Package frpc 负责以子进程方式托管官方 frpc 客户端。
//
// 之所以不内嵌 frp 库：官方 frpc 二进制稳定、可独立升级，且能直接复用
// 控制面下发的标准 frpc.toml，避免与 frp 内部 API 产生耦合。
//
// 一个 Manager 托管**多条隧道各自的 frpc 进程**：每条隧道一个进程，
// 配置文件也只含这一条隧道。早期版本是单个进程承载全部隧道，代价是
// 「改一条隧道，其他隧道全断一下」；而且所有隧道共用一个登录会话与
// 运行 ID，日志里分不出哪一行属于哪条隧道。
package frpc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// maxLogLines 内存中保留的日志行数。
const maxLogLines = 500

// ErrAlreadyRunning 表示该隧道的 frpc 已在运行。
var ErrAlreadyRunning = errors.New("该隧道的 frpc 已在运行")

// process 是某一条隧道的 frpc 进程。
type process struct {
	// name 只用于日志前缀。进程本身不认隧道名，改名不影响运行中的连接。
	name string
	cmd  *exec.Cmd

	// exitCh 在进程**真正**退出（Wait 返回）时关闭。
	//
	// 存在的意义：Kill 只是「发出终止信号」，进程可能还要几毫秒才消失。
	// 没有它就无法保证「Stop 返回时进程一定已经不在」，
	// 而这恰恰是紧接着调用 Start 的前提条件。
	exitCh chan struct{}
}

// Manager 托管多条隧道的 frpc 子进程。
type Manager struct {
	mu    sync.Mutex
	procs map[uint]*process
	logs  []string

	exePath string

	// onLog 收到的行已经带好「Tunnel/<名字>」前缀。
	onLog func(tunnelID uint, tunnelName, line string)
	// onExit 在某个隧道的进程退出时调用（包括被 Stop 主动停掉）。
	onExit func(tunnelID uint, tunnelName string, err error)
}

// New 创建管理器。exePath 为空时自动在应用目录与 PATH 中查找 frpc。
func New(exePath string) *Manager {
	if exePath == "" {
		exePath = findFrpc()
	}
	return &Manager{exePath: exePath, procs: map[uint]*process{}}
}

// SetCallbacks 注册日志与退出回调。回调会在后台协程中被调用。
func (m *Manager) SetCallbacks(
	onLog func(tunnelID uint, tunnelName, line string),
	onExit func(tunnelID uint, tunnelName string, err error),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLog = onLog
	m.onExit = onExit
}

// ExePath 返回解析到的 frpc 路径。
func (m *Manager) ExePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exePath
}

// Available 表示是否找到可用的 frpc。
func (m *Manager) Available() bool {
	p := m.ExePath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// Running 返回某条隧道的 frpc 是否正在运行。
func (m *Manager) Running(tunnelID uint) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.procs[tunnelID]
	return ok
}

// RunningIDs 返回当前正在运行的隧道 ID。
func (m *Manager) RunningIDs() []uint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint, 0, len(m.procs))
	for id := range m.procs {
		out = append(out, id)
	}
	return out
}

// TunnelName 返回某条隧道进程在日志里用的名字；该隧道没有进程时返回空串。
//
// 用途：隧道在服务端被删掉之后，客户端只剩一个隧道 ID，日志前缀需要靠它
// 还原——否则那条「正在断开」的日志会以 #12 这种形式出现，用户对不上号。
func (m *Manager) TunnelName(tunnelID uint) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[tunnelID]; ok {
		return p.name
	}
	return ""
}

// AnyRunning 表示是否有任意一条隧道在运行。
func (m *Manager) AnyRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.procs) > 0
}

// Start 以指定配置文件为某条隧道启动 frpc。
//
// tunnelName 只用于日志前缀：进程本身只认配置文件，
// 不依赖隧道名字，因此改名不影响正在运行的连接。
func (m *Manager) Start(tunnelID uint, tunnelName, configPath string) error {
	m.mu.Lock()
	if _, ok := m.procs[tunnelID]; ok {
		m.mu.Unlock()
		return ErrAlreadyRunning
	}
	exe := m.exePath
	if exe == "" {
		m.mu.Unlock()
		return errors.New("未找到 frpc 可执行文件，请将其放置到程序同目录")
	}
	if _, err := os.Stat(configPath); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("配置文件不可用: %w", err)
	}

	cmd := exec.Command(exe, "-c", configPath)
	cmd.Dir = filepath.Dir(configPath)
	// 不弹出黑色控制台窗口。
	hideWindow(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("启动 frpc 失败: %w", err)
	}

	exitCh := make(chan struct{})
	m.procs[tunnelID] = &process{name: tunnelName, cmd: cmd, exitCh: exitCh}
	onExit := m.onExit
	m.mu.Unlock()

	m.appendLog(tunnelID, tunnelName, fmt.Sprintf("已启动 frpc（PID %d）", cmd.Process.Pid))

	// 把子进程绑到一个「随本进程终止而终止」的 Job Object。
	//
	// Windows 上父进程退出不会自动结束子进程，不绑的话用户关掉客户端后
	// frpc 会继续在后台跑。放在解锁之后调用：它会做几次系统调用，
	// 没必要占着锁。
	//
	// 失败不致命（会退化为「仅在正常关闭时清理」），所以只记一行日志。
	if err := attachToJob(cmd); err != nil {
		m.appendLog(tunnelID, tunnelName, "提示：未能绑定进程生命周期，异常退出时可能残留 frpc 进程")
	}

	go m.pump(tunnelID, tunnelName, stdout)
	go m.pump(tunnelID, tunnelName, stderr)

	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		// 只清理仍指向本进程的记录：Stop 后紧接着 Start 会放入新的 *process，
		// 这里无条件删除会把刚起来的那个进程从表里抹掉，
		// 表现为「界面上显示未运行，实际进程还在」。
		if p, ok := m.procs[tunnelID]; ok && p.exitCh == exitCh {
			delete(m.procs, tunnelID)
		}
		m.mu.Unlock()
		// 先通知等待者再写日志：让 Stop 尽早返回，
		// 避免日志写入（可能触发前端事件）拖慢重启。
		close(exitCh)

		if err != nil {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出："+err.Error())
		} else {
			m.appendLog(tunnelID, tunnelName, "frpc 已正常退出")
		}
		if onExit != nil {
			onExit(tunnelID, tunnelName, err)
		}
	}()

	return nil
}

// Stop 停止某条隧道的 frpc 进程。
func (m *Manager) Stop(tunnelID uint) error {
	m.mu.Lock()
	p := m.procs[tunnelID]
	m.mu.Unlock()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	m.appendLog(tunnelID, p.name, "正在停止 frpc…")
	// 进程可能在我们拿到锁之前就自己退出了（frpc 启动失败就是这种情况），
	// 此时 Kill 返回 ErrProcessDone——那不是错误，目标已经达成。
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("停止 frpc 失败: %w", err)
	}

	// 等进程真正退出再返回。
	//
	// 不等的话，紧接着调用 Start 会撞上 ErrAlreadyRunning——
	// 因为进程记录是在 Wait 的协程里才被删除的。
	if p.exitCh != nil {
		select {
		case <-p.exitCh:
		case <-time.After(5 * time.Second):
			// 极端情况：Kill 之后进程仍未退出。
			// 不无限等待，让上层能给出提示，而不是把界面卡死。
			return errors.New("等待 frpc 退出超时")
		}
	}
	return nil
}

// StopAll 停止全部隧道的 frpc 进程，返回第一个错误。
func (m *Manager) StopAll() error {
	var firstErr error
	for _, id := range m.RunningIDs() {
		if err := m.Stop(id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Logs 返回日志快照。
func (m *Manager) Logs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.logs))
	copy(out, m.logs)
	return out
}

// ClearLogs 清空日志缓冲。
func (m *Manager) ClearLogs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = nil
}

func (m *Manager) pump(tunnelID uint, tunnelName string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		m.appendLog(tunnelID, tunnelName, scanner.Text())
	}
}

func (m *Manager) appendLog(tunnelID uint, tunnelName string, line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	stamped := fmt.Sprintf("%s  %s  %s", time.Now().Format("15:04:05"), logPrefix(tunnelID, tunnelName), line)

	m.mu.Lock()
	m.logs = append(m.logs, stamped)
	if len(m.logs) > maxLogLines {
		m.logs = m.logs[len(m.logs)-maxLogLines:]
	}
	cb := m.onLog
	m.mu.Unlock()

	if cb != nil {
		cb(tunnelID, tunnelName, stamped)
	}
}

// logPrefix 生成日志行的隧道前缀。
//
// 每条隧道一个进程之后，日志区是多个进程输出交织在一起，
// 没有前缀就完全读不出「哪条隧道出了什么问题」。
func logPrefix(tunnelID uint, tunnelName string) string {
	if tunnelName != "" {
		return "Tunnel/" + tunnelName
	}
	return fmt.Sprintf("Tunnel/#%d", tunnelID)
}

// StripLogPrefix 去掉日志行上的「时间 + Tunnel/<名字>」前缀，只留原文。
//
// 前缀由本包的 appendLog 拼成，格式固定为
//
//	<时间>  Tunnel/<名字>  <原文>
//
// 调用方需要看 frpc 原文时（例如判断这行是不是报错）必须先把前缀剥掉：
// 隧道名是用户自己取的，一个叫 errorlog 的隧道不该让它的正常输出被当成错误。
//
// 剥离方式是「跳过时间后的第一个双空格，再找下一个双空格」，而不是直接找
// 最后一个双空格：frpc 自己的输出里也可能出现连续空格，从后面切会把原文
// 截断（例如把 "[mc] start error: x" 截成 "x"），而这段原文正是要给用户看的。
func StripLogPrefix(line string) string {
	afterTime := strings.Index(line, "  ")
	if afterTime < 0 {
		return line
	}
	rest := line[afterTime+2:]
	afterPrefix := strings.Index(rest, "  ")
	if afterPrefix < 0 {
		return line
	}
	return rest[afterPrefix+2:]
}

// IsErrorLine 判断一行 frpc 输出是否表示出错。
//
// frpc 的失败输出形如：
//
//	[W] [client/control.go:172] [run id] [mc] start error: 隧道不存在…
//	[E] [client/service.go:312] login to server failed: …
//
// 它没有结构化字段可用，只能按关键词识别；error / failed 覆盖了它的全部
// 失败路径。判定前先剥掉前缀，避免隧道名本身带出误判。
func IsErrorLine(line string) bool {
	l := strings.ToLower(StripLogPrefix(line))
	return strings.Contains(l, "error") || strings.Contains(l, "failed")
}

// findFrpc 依次在可执行文件目录、当前目录与 PATH 中查找 frpc。
func findFrpc() string {
	name := "frpc"
	if runtime.GOOS == "windows" {
		name = "frpc.exe"
	}

	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, name),
			filepath.Join(dir, "bin", name),
			filepath.Join(dir, "resources", name),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, name))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}
