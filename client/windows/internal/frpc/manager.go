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
	"unicode/utf8"
)

// maxLogLines 内存中保留的日志行数。
const maxLogLines = 500

// maxLogBytes 是内存里保留日志的**总字节**上限。
//
// 只限行数不够：单行可以留到 1 MiB（见 pumpLineLimit），500 行就是 500 MiB
// ——而日志洪峰恰恰出现在客户端出问题的时候，那时最不该把内存吃光。
const maxLogBytes = 512 * 1024

// maxLogLineBytes 是单行进入日志缓冲时的保留上限。
//
// 与 pumpLineLimit 是两件事：后者管「读管道时一行最多吞多少」，这里管
// 「进日志缓冲时一行最多占多少」。一行 1 MiB 会自己吃掉整个字节预算，
// 把前面所有有用的行挤出去，而它的信息量并不比前 8 KiB 多。
const maxLogLineBytes = 8 * 1024

// ErrAlreadyRunning 表示该隧道的 frpc 已在运行。
var ErrAlreadyRunning = errors.New("该隧道的 frpc 已在运行")

// ErrClosed 表示管理器已进入关闭状态，不再启动新进程。
//
// 关闭是**单向**的：Close 之后 Start 永远失败。退出流程靠它兜住
// 「同步在 StopAll 之后才把进程拉起来」这一类漏网。
var ErrClosed = errors.New("客户端正在退出，不再启动 frpc")

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

	// stopping 表示这次退出是 Stop 主动请求的，而不是 frpc 自己崩了。
	//
	// 必须区分：Kill 之后 Wait 返回的同样是「非正常退出」的错误，
	// 上层若据此启动退避重试，用户每关一次开关就会看到一串
	// 「启动失败，30 秒后重试」——而那正是他自己要求的停止。
	stopping bool
}

// Manager 托管多条隧道的 frpc 子进程。
type Manager struct {
	mu    sync.Mutex
	procs map[uint]*process
	logs  []string
	// logBytes 是 logs 里所有行的总字节数，用于按字节预算裁剪。
	logBytes int

	exePath string

	// closed 表示已进入关闭流程：此后 Start 直接失败，见 Close。
	closed bool

	// 重复行合并状态：frpc 在「本地服务没起来」时会为每一次连接失败
	// 打一行完全相同的错误，被扫描或压测时一秒能刷几百行。
	//
	// 只保留第一行、其余计数，等下一行不同内容时补一条「重复 N 次」：
	// 用户仍然知道发生过什么，而日志缓冲不会被同一条错误挤满。
	repeatKey        string
	repeatAt         time.Time
	repeatCount      int
	repeatTunnelID   uint
	repeatTunnelName string

	// onLog 收到的行已经带好「Tunnel/<名字>」前缀。
	onLog func(tunnelID uint, tunnelName, line string)
	// onExit 在某个隧道的进程退出时调用。
	//
	// requested 为 true 表示这次退出是 Stop 主动请求的（用户关掉开关、
	// 退出登录、配置变更重连），而不是 frpc 自己退出——上层据此决定
	// 要不要进入退避重试。判错的后果很直观：用户关掉一条隧道，
	// 界面却开始报「启动失败，30 秒后重试」。
	onExit func(tunnelID uint, tunnelName string, err error, requested bool)
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
	onExit func(tunnelID uint, tunnelName string, err error, requested bool),
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
	// 关闭之后不再放行任何新进程：关闭流程是「关闸 → 停全部」，
	// 反过来的话与它并发的调用方能在 StopAll 之后拉起一个漏网进程。
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

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		m.pump(tunnelID, tunnelName, stdout)
	}()
	go func() {
		defer pumps.Done()
		m.pump(tunnelID, tunnelName, stderr)
	}()

	go func() {
		// 等两个读取协程收工，再 Wait。
		//
		// os/exec 的文档写得很明确：Wait 会关闭管道，所以「在读完管道之前
		// 调用 Wait」是不对的。进程退出时管道里往往还有最后几行没读完，
		// 而最后几行恰恰是崩溃原因——那几行就这么丢了，日志会停在
		// 一个看不出所以然的地方。
		//
		// 读取端会在写端关闭（进程退出）时自然拿到 EOF，正常情况下这里
		// 只是多等几毫秒。超时是防御性的：万一有孙进程继承了管道，
		// 不能让整个退出流程挂在原地——Stop 的 5 秒超时也在等这一步。
		drained := make(chan struct{})
		go func() {
			pumps.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			m.appendLog(tunnelID, tunnelName, "日志管道未在 2 秒内读取完毕，可能仍有输出未被记录")
		}

		err := cmd.Wait()

		m.mu.Lock()
		// 只清理仍指向本进程的记录：Stop 后紧接着 Start 会放入新的 *process，
		// 这里无条件删除会把刚起来的那个进程从表里抹掉，
		// 表现为「界面上显示未运行，实际进程还在」。
		requested := false
		current := false
		if p, ok := m.procs[tunnelID]; ok && p.exitCh == exitCh {
			requested = p.stopping
			delete(m.procs, tunnelID)
			current = true
		}
		m.mu.Unlock()
		// 先通知等待者再写日志：让 Stop 尽早返回，
		// 避免日志写入（可能触发前端事件）拖慢重启。
		close(exitCh)

		if !current {
			// 这个进程已经被同一隧道的新进程取代了（Stop 之后紧接 Start
			// 时，close(exitCh) 会让 Stop 先返回，回调可能随后才跑到这里）。
			//
			// exitCh 必须照常关闭（Stop 正在等它），但**不能**再回调 onExit：
			// 上层会用这个回调清掉「已注册」标记，而那个标记现在是新进程的
			// ——结果就是刚刚连上的隧道被标成「未连接」，用户看到刚打开
			// 又变回未连接，然后下一轮同步才纠正。
			//
			// 日志照记：进程确实退出了，排查时需要看到它。
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			return
		}

		if err != nil {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出："+err.Error())
		} else {
			m.appendLog(tunnelID, tunnelName, "frpc 已正常退出")
		}
		if onExit != nil {
			onExit(tunnelID, tunnelName, err, requested)
		}
	}()

	return nil
}

// Stop 停止某条隧道的 frpc 进程。
func (m *Manager) Stop(tunnelID uint) error {
	m.mu.Lock()
	p := m.procs[tunnelID]
	if p != nil {
		// 先标记再 Kill：Wait 的协程可能在任何时刻读到它。
		p.stopping = true
	}
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

// Close 进入关闭状态并停止全部进程，返回第一个错误。
//
// 顺序必须是「先关闸、后停进程」：只调 StopAll 的话，与退出并发的一轮
// 同步可以在 StopAll 之后拿到配置并拉起新进程——那个进程就没人管了
// （Job Object 绑定失败时尤其明显）。
func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return m.StopAll()
}

// Closed 报告是否已进入关闭状态。
func (m *Manager) Closed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
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
	m.logBytes = 0
	// 重复行合并状态也要清：留着的话，清空后的第一条日志如果恰好与
	// 清空前那条相同，会被当成「重复」直接吞掉，用户以为清空把新日志也弄没了。
	m.repeatKey = ""
	m.repeatCount = 0
	m.repeatAt = time.Time{}
}

// pumpLineLimit 是单行日志保留的字节上限，超出的部分截断丢弃。
//
// frpc 的正常输出远小于它。超限不是「停止读取」的理由：读取端一旦停摆，
// 管道写满之后子进程就阻塞在写日志上——它既不退出也不响应，Wait 永远
// 不返回，界面上那条隧道会一直是「运行中」。
const pumpLineLimit = 1024 * 1024

func (m *Manager) pump(tunnelID uint, tunnelName string, r io.Reader) {
	// 用 ReadSlice 而不是 bufio.Scanner：Scanner 遇到超过上限的行会返回
	// ErrTooLong 并**停止读取**，剩下的输出没人消费，子进程就卡在写管道上。
	// 这里超限只截断日志内容，读取照常继续到换行、继续跟进后面的行。
	br := bufio.NewReaderSize(r, 64*1024)

	var (
		line      []byte
		truncated bool
	)
	// flush 把攒好的一行交出去。超限的标记只加在日志里，不改变「已经读到
	// 换行」这个事实——后续输出必须继续被消费。
	flush := func() {
		text := string(line)
		if truncated {
			text += "（本行超过 1 MiB，其余内容已截断）"
		}
		m.appendLog(tunnelID, tunnelName, text)
		line = line[:0]
		truncated = false
	}

	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			if room := pumpLineLimit - len(line); room > 0 {
				if len(chunk) <= room {
					line = append(line, chunk...)
				} else {
					line = append(line, chunk[:room]...)
					truncated = true
				}
			} else {
				truncated = true
			}
		}

		switch {
		case err == nil:
			flush()
		case errors.Is(err, bufio.ErrBufferFull):
			// 还没读到换行：继续取同一行的后续片段。
			continue
		case errors.Is(err, io.EOF):
			// 最后一行没有换行符，同样要记下来。
			if len(line) > 0 || truncated {
				flush()
			}
			return
		default:
			if len(line) > 0 || truncated {
				flush()
			}
			// 读取失败必须留痕。
			//
			// 以前这里什么都不做：日志会凭空停在某一行，看起来像「frpc 不再
			// 输出了」，而真实原因是我们的读取端坏了（管道错误、卷被卸载）。
			// 这类现象最容易被归因到 frpc 或服务端，实际上问题在客户端自己。
			m.appendLog(tunnelID, tunnelName, "日志读取中断："+err.Error())
			return
		}
	}
}

// logRepeatWindow 是同一行连续出现时的合并窗口。
//
// 窗口内只计数不落行；窗口外仍在重复时补一条「重复 N 次」再继续，
// 否则持续压测下日志看起来像停住了。
const logRepeatWindow = 5 * time.Second

// logEntry 是一条已经带好前缀、等待同时写进缓冲并推给前端的日志。
type logEntry struct {
	id   uint
	name string
	text string
}

func (m *Manager) appendLog(tunnelID uint, tunnelName string, line string) {
	line = strings.TrimRight(line, "\r\n")
	line = clipLogLine(line, maxLogLineBytes)
	if line == "" {
		return
	}

	now := time.Now()
	key := fmt.Sprintf("%d\x00%s", tunnelID, line)

	m.mu.Lock()
	var out []logEntry
	// 重复窗口结束、或换了一条不同的日志：先把累计的重复次数交代掉。
	if m.repeatCount > 0 && (key != m.repeatKey || now.Sub(m.repeatAt) >= logRepeatWindow) {
		out = append(out, m.recordLocked(m.repeatTunnelID, m.repeatTunnelName,
			fmt.Sprintf("（上一条重复 %d 次，已合并）", m.repeatCount), now))
		m.repeatCount = 0
	}
	if key == m.repeatKey && now.Sub(m.repeatAt) < logRepeatWindow {
		m.repeatCount++
		m.repeatAt = now
		cb := m.onLog
		m.mu.Unlock()
		emitLogs(cb, out)
		return
	}
	m.repeatKey, m.repeatAt = key, now
	m.repeatTunnelID, m.repeatTunnelName = tunnelID, tunnelName
	out = append(out, m.recordLocked(tunnelID, tunnelName, line, now))
	cb := m.onLog
	m.mu.Unlock()

	emitLogs(cb, out)
}

func emitLogs(cb func(uint, string, string), entries []logEntry) {
	if cb == nil {
		return
	}
	for _, e := range entries {
		cb(e.id, e.name, e.text)
	}
}

// recordLocked 在已持有锁的前提下写入一行日志，返回可推送的副本。
func (m *Manager) recordLocked(tunnelID uint, tunnelName, line string, now time.Time) logEntry {
	stamped := fmt.Sprintf("%s  %s  %s", now.Format("15:04:05"), logPrefix(tunnelID, tunnelName), line)
	m.logs = append(m.logs, stamped)
	m.logBytes += len(stamped)

	// 先按行数裁，再按总字节裁：两个上限针对的是不同的失控方式
	// （行数爆炸 / 单行过大），只留一个都会被另一个绕过。
	if over := len(m.logs) - maxLogLines; over > 0 {
		for i := 0; i < over; i++ {
			m.logBytes -= len(m.logs[i])
		}
		m.logs = m.logs[over:]
	}
	for len(m.logs) > 1 && m.logBytes > maxLogBytes {
		m.logBytes -= len(m.logs[0])
		m.logs = m.logs[1:]
	}
	return logEntry{id: tunnelID, name: tunnelName, text: stamped}
}

// clipLogLine 把超长的单行截断，且不切断多字节字符。
func clipLogLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…（超长，已截断）"
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
