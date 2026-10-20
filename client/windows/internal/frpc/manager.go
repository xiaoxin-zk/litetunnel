package frpc

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var ErrAlreadyRunning = errors.New("该隧道的 frpc 已在运行")

var ErrClosed = errors.New("客户端正在退出，不再启动 frpc")

const exitLockShards = 32

func (m *Manager) stillCurrent(tunnelID uint, gen uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gens[tunnelID] == gen && !m.closed
}

func (m *Manager) Current(tunnelID uint, gen uint64) bool {
	return m.stillCurrent(tunnelID, gen)
}

func (m *Manager) SetTunnelAccount(tunnelID uint, acct uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accounts == nil {
		m.accounts = make(map[uint]uint64)
	}
	m.accounts[tunnelID] = acct
}

func (m *Manager) exitLock(tunnelID uint) *sync.Mutex {
	return &m.exitMu[tunnelID%exitLockShards]
}

func (m *Manager) opLock(tunnelID uint) *sync.Mutex {
	return &m.opMu[tunnelID%exitLockShards]
}

type process struct {
	name string
	cmd  *exec.Cmd

	gen uint64

	exitCh chan struct{}

	stopping bool
}

type Manager struct {
	mu       sync.Mutex
	procs    map[uint]*process
	logs     []LogEntry
	logBytes int

	exePath string

	accounts map[uint]uint64

	closed bool

	exitMu [exitLockShards]sync.Mutex

	opMu [exitLockShards]sync.Mutex

	callbackWG sync.WaitGroup

	gens   map[uint]uint64
	genSeq uint64

	repeatKey        string
	repeatAt         time.Time
	repeatCount      int
	repeatTunnelID   uint
	repeatTunnelName string
	repeatGen        uint64

	logSeq uint64

	pending        []logEntry
	emitWake       chan struct{}
	pendingDropped int
	emitQuit       chan struct{}
	emitOnce       sync.Once
	emitWG         sync.WaitGroup

	onLog     func(tunnelID uint, tunnelName string, seq uint64, line string)
	onLogGen  func(tunnelID uint, tunnelName string, gen uint64, seq uint64, line string)
	onLogAcct func(acct uint64, tunnelID uint, tunnelName string, gen uint64, seq uint64, line string)
	onExit    func(tunnelID uint, tunnelName string, err error, requested bool)
	onExitGen func(tunnelID uint, tunnelName string, gen uint64, err error, requested bool)
}

func New(exePath string) *Manager {
	if exePath == "" {
		exePath = findFrpc()
	}
	m := &Manager{
		exePath:  exePath,
		procs:    map[uint]*process{},
		gens:     map[uint]uint64{},
		emitWake: make(chan struct{}, 1),
		emitQuit: make(chan struct{}),
	}
	m.emitWG.Add(1)
	go m.dispatchLogs()
	return m
}

func (m *Manager) SetCallbacks(
	onLog func(tunnelID uint, tunnelName string, seq uint64, line string),
	onExit func(tunnelID uint, tunnelName string, err error, requested bool),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLog = onLog
	m.onExit = onExit
	m.onLogGen = nil
	m.onLogAcct = nil
	m.onExitGen = nil
}

func (m *Manager) SetGenerationCallbacks(
	onLog func(tunnelID uint, tunnelName string, gen uint64, seq uint64, line string),
	onExit func(tunnelID uint, tunnelName string, gen uint64, err error, requested bool),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLogGen = onLog
	m.onExitGen = onExit
	m.onLog = nil
	m.onLogAcct = nil
	m.onExit = nil
}

func (m *Manager) SetAccountCallbacks(
	onLog func(acct uint64, tunnelID uint, tunnelName string, gen uint64, seq uint64, line string),
	onExit func(tunnelID uint, tunnelName string, gen uint64, err error, requested bool),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLogAcct = onLog
	m.onExitGen = onExit
	m.onLog = nil
	m.onLogGen = nil
	m.onExit = nil
}

func (m *Manager) ExePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exePath
}

// SetExePath 延迟注入 frpc 路径：调用方可以先把窗口显示出来，
// 再把内嵌的 frpc 释放到磁盘，避免首次启动被 20MB 写盘挡住。
func (m *Manager) SetExePath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exePath = path
}

func (m *Manager) Available() bool {
	return usableExecutable(m.ExePath())
}

func (m *Manager) Gen(tunnelID uint) (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.procs[tunnelID]
	if !ok || p == nil {
		return 0, false
	}
	return p.gen, true
}

func (m *Manager) Running(tunnelID uint) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.procs[tunnelID]
	return ok
}

func (m *Manager) RunningSet() map[uint]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uint]struct{}, len(m.procs))
	for id := range m.procs {
		out[id] = struct{}{}
	}
	return out
}

func (m *Manager) RunningIDs() []uint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint, 0, len(m.procs))
	for id := range m.procs {
		out = append(out, id)
	}
	return out
}

func (m *Manager) TunnelName(tunnelID uint) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[tunnelID]; ok {
		return p.name
	}
	return ""
}

func (m *Manager) AnyRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.procs) > 0
}

func (m *Manager) Start(tunnelID uint, tunnelName, configPath string) error {
	op := m.opLock(tunnelID)
	op.Lock()
	defer op.Unlock()

	lock := m.exitLock(tunnelID)
	lock.Lock()
	defer lock.Unlock()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
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

	if err := attachToJob(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		m.mu.Unlock()
		return fmt.Errorf("无法绑定 frpc 进程生命周期，已终止该进程: %w", err)
	}

	exitCh := make(chan struct{})
	m.genSeq++
	gen := m.genSeq
	m.gens[tunnelID] = gen
	m.procs[tunnelID] = &process{name: tunnelName, cmd: cmd, exitCh: exitCh, gen: gen}
	onExit := m.onExit
	onExitGen := m.onExitGen
	m.mu.Unlock()

	m.appendLog(tunnelID, tunnelName, fmt.Sprintf("已启动 frpc（PID %d）", cmd.Process.Pid))

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		m.pumpGen(tunnelID, tunnelName, gen, stdout)
	}()
	go func() {
		defer pumps.Done()
		m.pumpGen(tunnelID, tunnelName, gen, stderr)
	}()

	go func() {
		defer func() {
			m.mu.Lock()
			if m.gens[tunnelID] == gen {
				delete(m.gens, tunnelID)
			}
			m.mu.Unlock()
		}()

		drained := make(chan struct{})
		go func() {
			pumps.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			m.appendLog(tunnelID, tunnelName, "日志管道未在 2 秒内读取完毕，可能仍有输出未被记录")
			_ = stdout.Close()
			_ = stderr.Close()
		}

		err := cmd.Wait()

		m.mu.Lock()
		requested := false
		current := false
		if p, ok := m.procs[tunnelID]; ok && p.exitCh == exitCh {
			requested = p.stopping
			delete(m.procs, tunnelID)
			current = true
		}
		m.mu.Unlock()

		exitLock := m.exitLock(tunnelID)
		exitLock.Lock()

		m.mu.Lock()
		stale := m.gens[tunnelID] != gen
		closing := m.closed
		dispatch := current && !stale && !closing && (onExit != nil || onExitGen != nil)
		if dispatch {
			m.callbackWG.Add(1)
			defer m.callbackWG.Done()
		}
		m.mu.Unlock()

		defer func() {
			if r := recover(); r != nil {
				m.appendLog(tunnelID, tunnelName, fmt.Sprintf("退出回调异常：%v", r))
			}
		}()

		close(exitCh)
		exitLock.Unlock()

		if !current {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			return
		}

		if err != nil {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出："+err.Error())
		} else {
			m.appendLog(tunnelID, tunnelName, "frpc 已正常退出")
		}

		if stale {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			return
		}
		if closing {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（客户端正在关闭，跳过退出回调）")
			return
		}
		if !dispatch {
			return
		}

		if !m.stillCurrent(tunnelID, gen) {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			return
		}
		if onExitGen != nil {
			onExitGen(tunnelID, tunnelName, gen, err, requested)
		} else if onExit != nil {
			onExit(tunnelID, tunnelName, err, requested)
		}
	}()

	return nil
}

const stopAttempts = 5

func (m *Manager) Stop(tunnelID uint) error {
	op := m.opLock(tunnelID)
	op.Lock()
	defer op.Unlock()

	for attempt := 0; ; attempt++ {
		m.mu.Lock()
		p := m.procs[tunnelID]
		if p != nil {
			p.stopping = true
		}
		m.mu.Unlock()
		if p == nil {
			return nil
		}
		if p.cmd == nil || p.cmd.Process == nil {
			if !m.waitExit(p, tunnelID) {
				return errors.New("等待 frpc 退出超时")
			}
		} else {
			m.appendLog(tunnelID, p.name, "正在停止 frpc…")
			if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return fmt.Errorf("停止 frpc 失败: %w", err)
			}
			if !m.waitExit(p, tunnelID) {
				return errors.New("等待 frpc 退出超时")
			}
		}

		m.mu.Lock()
		stillThere := m.procs[tunnelID] != nil
		m.mu.Unlock()
		if !stillThere {
			return nil
		}
		if attempt+1 >= stopAttempts {
			return errors.New("隧道在停止过程中被反复重新启动，请稍后重试")
		}
	}
}

func (m *Manager) waitExit(p *process, tunnelID uint) bool {
	if p.exitCh == nil {
		return true
	}
	select {
	case <-p.exitCh:
		return true
	case <-time.After(5 * time.Second):
		m.appendLog(tunnelID, p.name, "等待 frpc 退出超时，可能仍有残留进程")
		return false
	}
}

func (m *Manager) StopAll() error {
	ids := m.RunningIDs()
	if len(ids) == 0 {
		return nil
	}

	deadline := time.After(6 * time.Second)
	errCh := make(chan error, len(ids))
	for _, id := range ids {
		go func(id uint) {
			errCh <- m.Stop(id)
		}(id)
	}

	var firstErr error
	for range ids {
		select {
		case err := <-errCh:
			if err != nil && firstErr == nil {
				firstErr = err
			}
		case <-deadline:
			if m.AnyRunning() {
				if firstErr != nil {
					return fmt.Errorf("停止全部隧道超时，仍有进程未退出: %w", firstErr)
				}
				return errors.New("停止全部隧道超时，仍有进程未退出")
			}
			return firstErr
		}
	}
	return firstErr
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	err := m.StopAll()

	if !m.WaitCallbacks(2 * time.Second) {
		log.Printf("[frpc] 仍有退出回调未结束，继续关闭")
	}

	m.emitOnce.Do(func() { close(m.emitQuit) })
	done := make(chan struct{})
	go func() {
		m.emitWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		log.Printf("[frpc] 日志投递未在 2 秒内退出，继续关闭")
	}
	return err
}

func (m *Manager) WaitCallbacks(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		m.callbackWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		log.Printf("[frpc] 退出回调未在 %s 内结束，可能有迟到的回调落在清理之后", d)
		return false
	}
}

func (m *Manager) Closed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

var strictLookup bool

func SetStrictLookup(strict bool) { strictLookup = strict }

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
	for _, c := range candidates {
		if usableExecutable(c) {
			return c
		}
	}
	if strictLookup {
		return ""
	}
	if wd, err := os.Getwd(); err == nil {
		if c := filepath.Join(wd, name); usableExecutable(c) {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil && usableExecutable(p) {
		return p
	}
	return ""
}

func usableExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.IsDir() || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}
