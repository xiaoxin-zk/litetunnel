// Package frpc 负责以子进程方式托管官方 frpc 客户端。
//
// 之所以不内嵌 frp 库：官方 frpc 二进制稳定、可独立升级，且能直接复用
// 控制面下发的标准 frpc.toml，避免与 frp 内部 API 产生耦合。
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

// ErrAlreadyRunning 表示客户端已在运行。
var ErrAlreadyRunning = errors.New("客户端已在运行")

// Manager 管理 frpc 子进程的生命周期。
type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	logs    []string

	exePath string

	onLog  func(string)
	onExit func(err error)
}

// New 创建管理器。exePath 为空时自动在应用目录与 PATH 中查找 frpc。
func New(exePath string) *Manager {
	if exePath == "" {
		exePath = findFrpc()
	}
	return &Manager{exePath: exePath}
}

// SetCallbacks 注册日志与退出回调。回调会在后台协程中被调用。
func (m *Manager) SetCallbacks(onLog func(string), onExit func(error)) {
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

// Running 返回是否正在运行。
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Start 以指定配置文件启动 frpc。
func (m *Manager) Start(configPath string) error {
	m.mu.Lock()
	if m.running {
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

	m.cmd = cmd
	m.running = true
	m.logs = nil
	onLog := m.onLog
	onExit := m.onExit
	m.mu.Unlock()

	m.appendLog(fmt.Sprintf("[系统] 已启动 frpc（PID %d）", cmd.Process.Pid))

	go m.pump(stdout)
	go m.pump(stderr)

	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.cmd = nil
		m.mu.Unlock()

		if err != nil {
			m.appendLog("[系统] frpc 已退出：" + err.Error())
		} else {
			m.appendLog("[系统] frpc 已正常退出")
		}
		if onExit != nil {
			onExit(err)
		}
	}()

	_ = onLog
	return nil
}

// Stop 停止 frpc 进程。
func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	m.appendLog("[系统] 正在停止 frpc…")
	if err := cmd.Process.Kill(); err != nil {
		return fmt.Errorf("停止 frpc 失败: %w", err)
	}
	return nil
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

func (m *Manager) pump(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		m.appendLog(scanner.Text())
	}
}

func (m *Manager) appendLog(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	stamped := time.Now().Format("15:04:05") + "  " + line

	m.mu.Lock()
	m.logs = append(m.logs, stamped)
	if len(m.logs) > maxLogLines {
		m.logs = m.logs[len(m.logs)-maxLogLines:]
	}
	cb := m.onLog
	m.mu.Unlock()

	if cb != nil {
		cb(stamped)
	}
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
