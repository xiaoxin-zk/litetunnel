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

// ErrAlreadyRunning 表示该隧道的 frpc 已在运行。
var ErrAlreadyRunning = errors.New("该隧道的 frpc 已在运行")

// ErrClosed 表示管理器已进入关闭状态，不再启动新进程。
//
// 关闭是**单向**的：Close 之后 Start 永远失败。退出流程靠它兜住
// 「同步在 StopAll 之后才把进程拉起来」这一类漏网。
var ErrClosed = errors.New("客户端正在退出，不再启动 frpc")

// exitLockShards 是「退出回调 ↔ 新进程登记」互斥锁的分片数。
//
// 固定分片没有清理问题；碰撞只让两条不相干隧道的启动多串行一点，
// 而这类操作本来就很稀疏。
const exitLockShards = 32

// stillCurrent 报告该隧道是否仍是这一代进程、且客户端未进入关闭。
//
// 用于回调派发前的最后一道核对：此时已经不持锁，只能靠代次确认。
func (m *Manager) stillCurrent(tunnelID uint, gen uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gens[tunnelID] == gen && !m.closed
}

// exitLock 返回某条隧道的退出回调锁。
func (m *Manager) exitLock(tunnelID uint) *sync.Mutex {
	return &m.exitMu[tunnelID%exitLockShards]
}

// process 是某一条隧道的 frpc 进程。
type process struct {
	// name 只用于日志前缀。进程本身不认隧道名，改名不影响运行中的连接。
	name string
	cmd  *exec.Cmd

	// gen 是这条隧道第几次启动。旧进程退出时靠它判断「自己还是不是最新的」。
	gen uint64

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
	// logs 保存带序号的日志行。序号让调用方能把快照与实时事件对齐，
	// 避免「快照里已有的行又被实时事件追加一次」。
	logs []LogEntry
	// logBytes 是 logs 里所有行的总字节数，用于按字节预算裁剪。
	logBytes int

	exePath string

	// closed 表示已进入关闭流程：此后 Start 直接失败，见 Close。
	closed bool

	// exitMu 按隧道分片，串行化「派发某条隧道的退出回调」与「为同一条隧道
	// 登记新进程」。
	//
	// 只靠 procs 里是否还有本进程来判断是不够的：Wait 协程删掉记录、关闭
	// exitCh 之后，Stop 立刻返回，新进程可能在此刻完成登记，而旧回调还没
	// 开始执行——它会把刚连上的隧道标成「未连接」。
	// 两边都持同一分片的锁之后，二者只可能是先后关系。
	//
	// 分片而不是全局一把：回调会调用上层（发 Wails 事件、写日志、刷状态），
	// 一次阻塞不该让**所有**隧道的启动与退出处理一起排队。
	//
	// 锁序固定为 exitMu → mu，与下面 Start 和 Wait 协程的取法一致。
	exitMu [exitLockShards]sync.Mutex

	// callbackWG 统计正在执行的退出回调。Close 要等它们结束：
	// 关闭流程接下来会拆掉日志投递，回调若仍在往队列里写，收尾日志会丢。
	callbackWG sync.WaitGroup

	// gens 记录每条隧道最近一次启动的代次，进程退出后仍然保留：
	// 它是「旧回调是否已过期」的唯一判据，删掉就等于失去判断依据。
	// 条目数与历史隧道数同阶（每条隧道一项），不随重启次数增长。
	gens   map[uint]uint64
	genSeq uint64

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

	// logSeq 是日志行的单调序号，清空之后仍然继续递增。
	//
	// 用途是过滤「清空前产生、清空后才送达」的在途行：调用方记下清空时的
	// 序号，之后收到的行只要序号不大于它就直接丢弃。只按内容或时间戳判断
	// 都不可靠——秒级时间戳分不出先后，内容更可能与新日志相同。
	logSeq uint64

	// pending 是待投递的日志，由投递协程按入队顺序取出。
	//
	// 回调不能在持锁时调用：上层收到「start proxy success」会顺手写一条
	// 说明日志（emitTunnelLog → AppendRaw），那会再次请求这把不可重入的锁，
	// 直接死锁。也不能在解锁后直接调用：两条隧道并发输出时序号会乱序，
	// 调用方按序号去重就会丢掉迟到的较小序号。因此「加锁入队、解锁后
	// 由单一协程按序投递」。
	pending  []logEntry
	emitWake chan struct{}
	// pendingDropped 记录投递队列溢出时被丢掉的条数，由投递协程补一条
	// 合成记录说明「中间还有 N 行没显示」——静默丢弃会让用户以为日志完整。
	pendingDropped int
	// emitQuit 关闭后投递协程把剩余队列排空即退出；emitWG 供 Close 等待。
	emitQuit chan struct{}
	emitOnce sync.Once
	emitWG   sync.WaitGroup

	// onLog 收到的行已经带好前缀；seq 是该行的单调序号。
	onLog func(tunnelID uint, tunnelName string, seq uint64, line string)
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

// SetCallbacks 注册日志与退出回调。回调会在后台协程中被调用。
func (m *Manager) SetCallbacks(
	onLog func(tunnelID uint, tunnelName string, seq uint64, line string),
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
	// 持该隧道的 exitMu 分片直到本函数返回：这段时间里它的旧退出回调不会
	// 执行，因此不可能出现「回调先跑、把刚登记的新进程当成已退出」的覆盖。
	// 反过来若回调先拿到锁，它会先于本次登记执行完——那时新进程还不存在，
	// 上层清掉的状态随后会被新进程的 start proxy success 重新置位。
	lock := m.exitLock(tunnelID)
	lock.Lock()
	defer lock.Unlock()

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
	m.genSeq++
	gen := m.genSeq
	m.gens[tunnelID] = gen
	m.procs[tunnelID] = &process{name: tunnelName, cmd: cmd, exitCh: exitCh, gen: gen}
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

		// 回调登记必须在 close(exitCh) **之前**完成。
		//
		// Stop/StopAll 是「看到 exitCh 关闭就返回」的，而上层在 StopAll 之后
		// 会调用 WaitCallbacks 等这批回调落地，再清凭据。Add 若晚于 close，
		// 那一刻计数还是零，Wait 会立刻返回——等待点形同虚设，迟到的回调
		// 照样能落到已经清完凭据的新账号状态上。
		exitLock := m.exitLock(tunnelID)
		exitLock.Lock()

		m.mu.Lock()
		stale := m.gens[tunnelID] != gen
		closing := m.closed
		// 必须在 mu 内登记：Close 先置 closed 再 Wait，两条路径只可能是先后
		// 关系——这里读到 false 并 Add 之后才会有人置 true，而那时 Add 已经
		// 完成，Wait 一定能等到。
		dispatch := current && !stale && !closing && onExit != nil
		if dispatch {
			m.callbackWG.Add(1)
		}
		m.mu.Unlock()

		// 先通知等待者再写日志：让 Stop 尽早返回，
		// 避免日志写入（可能触发前端事件）拖慢重启。
		close(exitCh)
		exitLock.Unlock()

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

		// 这里只做「代次校验 + 回调派发」，**不在锁内执行回调**。
		//
		// 早先的实现把 onExit 放在这把锁里：onExit 会发 Wails 事件、刷界面
		// 状态，UI 一旦阻塞，同一条隧道的启停就跟着排队。锁按隧道分片只
		// 解决了「别的隧道被拖住」这一点，同一条隧道仍然会被拖。
		if stale {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			return
		}
		if closing {
			// 关闭阶段不再回调：接下来 Wails 运行时与日志投递都要拆掉，
			// 回调里的状态写入与事件发送没有接收方，还可能落在一个
			// 已经销毁的目标上。
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（客户端正在关闭，跳过退出回调）")
			return
		}
		if !dispatch {
			// onExit 为 nil：没有回调可派发（Add 也没做过，不需要 Done）。
			return
		}

		// 锁外派发。代价是「校验 → 回调写入」之间重新出现窗口：新进程可能
		// 在这期间登记，回调会把它的状态清掉。派发前再核对一次代次（Start
		// 登记时会先递增 gens，这里看得见），把窗口压到两次内存读之间。
		//
		// 这个残余窗口无法靠锁消除：要彻底关掉，得让上层记录的「已注册」
		// 也带上代次，那是改回调签名的事，影响面大于收益。实际后果也有限
		// ——新进程接下来会因 "start proxy success" 重新置位。
		if !m.stillCurrent(tunnelID, gen) {
			m.appendLog(tunnelID, tunnelName, "frpc 已退出（该隧道已启动新进程，忽略本次退出回调）")
			m.callbackWG.Done()
			return
		}
		onExit(tunnelID, tunnelName, err, requested)
		m.callbackWG.Done()
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
//
// 并行发终止请求、统一等待：串行的话每条最多等 5 秒，N 条就是 5N 秒，
// 大量隧道同时退出时注销或关窗会等几十秒。并行后总等待约为单个 5 秒超时。
// 全局 deadline 再兜一层底：即使个别进程的等待卡住，也保证在 deadline 内返回。
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
			// 不再等剩余进程：它们的 Stop 自带 5 秒超时，稍后会自行结束。
			return firstErr
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
	err := m.StopAll()

	// StopAll 只等到 exitCh 关闭（进程确实退出），而退出回调是在那之后
	// 才执行的。这里再等回调收尾：它们会写日志、发状态事件，而下面就要
	// 停掉日志投递，上层随后还会销毁 Wails 运行时。
	if !m.WaitCallbacks(2 * time.Second) {
		log.Printf("[frpc] 仍有退出回调未结束，继续关闭")
	}

	// 停完进程再停投递：进程退出的收尾日志已经进了队列，
	// 立刻掐掉投递协程会把它们吞掉。
	m.emitOnce.Do(func() { close(m.emitQuit) })
	done := make(chan struct{})
	go func() {
		m.emitWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// 回调卡住时不能让退出流程无限等待：日志可以丢，进程必须退。
		log.Printf("[frpc] 日志投递未在 2 秒内退出，继续关闭")
	}
	return err
}

// WaitCallbacks 等所有在途的退出回调执行完毕，最多等 d。
//
// 返回 true 表示全部回调都已落地；false 表示等到上限还没等到（已记一行日志）。
//
// 给上层用的原因：StopAll 只等到「进程真的退出」（exitCh 关闭），而 onExit
// 是在那之后才执行的。退出登录要清凭据、清隧道配置，而一个迟到的退出回调
// 会在清理之后才跑：它会拿旧进程的结局去改**新账号**的运行态——把刚连上的
// 隧道标成未连接、或替新账号推进一次退避，而它描述的那个进程早就跟当前
// 账号无关了。
//
// 所以登出流程必须在「停止进程」与「清凭据」之间插一个等待点：先让这批
// 回调落地（它们此刻带的还是旧代次），再翻转代次与凭据。顺序反过来的话，
// 迟到的回调会被自己的代次校验放过，污染的就是新账号的状态。
//
// 能等到是因为 callbackWG 的 Add 挪到了 close(exitCh) **之前**：
// Stop/StopAll 一看到 exitCh 关闭就返回，Add 若晚于它，这里的 Wait 会在
// 计数为零时立刻返回，等待就形同虚设（见 Start 里的退出协程）。
//
// 上限是必要的：回调会发 Wails 事件，界面线程卡住时可能长时间不返回。
// 日志可以丢，进程必须退——退出登录不能因为一个回调卡死。
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

// Closed 报告是否已进入关闭状态。
func (m *Manager) Closed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
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
