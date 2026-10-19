package main

import (
	"fmt"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

// maxStatusTextRunes 是错误/状态文本保留的最大字符数。
//
// 这些文本来自服务端响应与 frpc 输出，最终会随每次 GetState 通过 IPC
// 送给前端。不设上限时，一次异常响应（例如带整段 HTML 的 502 页面）会被
// 原样保留并在每次状态事件里重复序列化——内存与 IPC 都被一条消息放大。
// 保留开头而不是结尾：错误的首行通常就说明了原因。
const maxStatusTextRunes = 400

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// clampStatusText 按字符（而不是字节）截断，避免把 UTF-8 字符切成半个。
func clampStatusText(s string) string {
	r := []rune(s)
	if len(r) <= maxStatusTextRunes {
		return s
	}
	return string(r[:maxStatusTextRunes]) + "…（已截断）"
}

func (a *App) setSyncErr(err error) {
	a.mu.Lock()
	a.syncErr = clampStatusText(err.Error())
	a.mu.Unlock()
}

func (a *App) emitState() {
	if a.ctx == nil {
		return
	}
	// 取号与取快照必须在**同一把锁**内完成（见 State.StateSeq / AuthGen）。
	//
	// 分两步做（先 GetState 再 nextStateSeq）会留下一个致命窗口：
	// GetState 拿读锁取完快照、放锁之后，logout 可能插进来翻代次并推送
	// 新状态，然后这里才取到更大的序号——于是这份「旧代次的快照」带着
	// 最大的序号发出去，前端按序号判断会接受它，界面被旧状态覆盖。
	//
	// 一次持锁做完就没有这个窗口：快照、序号、代次三者取自同一时刻，
	// 前端按 (auth_gen, state_seq) 排序时结论必然与真实先后一致。
	seq, gen, st := a.snapshotForEmit()
	st.StateSeq = seq
	st.AuthGen = gen
	wailsruntime.EventsEmit(a.ctx, "state", st)
}

// snapshotForEmit 在**一次持锁**内取状态快照、下一个序号、当前账号代次。
//
// 抽出来是为了让「三者同源」这件事在代码里可见：任何一处漏在同一把锁内
// 取，都会重新引入「旧代次快照配新序号」的窗口。
func (a *App) snapshotForEmit() (seq, gen uint64, st State) {
	// 日志代次与 GetState 一样，必须在拿 a.mu 之前读（logMu 的锁序，见
	// GetState 的说明）。
	logEpoch := a.currentLogEpoch()

	// 用写锁而不是读锁：这里要自增 stateSeq，读锁下写共享字段是数据竞争。
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stateSeq++
	seq = a.stateSeq
	gen = a.authGeneration
	st = a.getStateLocked(logEpoch)
	return seq, gen, st
}

// stateEmitMinInterval 是合并状态推送的最小间隔。
//
// 100ms 足以把「一次连接失败刷出上千行」压成每秒十次推送，又不会让人眼
// 察觉到延迟；再大（比如 500ms）就会让用户点开关后觉得界面「卡了一下」。
const stateEmitMinInterval = 100 * time.Millisecond

// requestState 请求一次状态推送，**不阻塞调用方**。
//
// 存在的理由：日志回调原先直接调用 emitState，而 emitState 最终落到
// wailsruntime.EventsEmit —— 在 Windows 上它是同步的，会一直等到 UI 线程
// 空闲。于是 UI 卡一秒，日志投递协程就卡一秒：所有隧道的日志一起停摆，
// 积压到上限后开始丢行，而丢掉的恰恰是解释「为什么卡住」的那些行。
//
// 这里只做一次非阻塞发送；真正的序列化与推送在独立的合并协程里完成
// （见 stateLoop）。通道容量 1 意味着「已经有人排着了」时就合并掉——
// 状态是快照语义，中间那次推送本来就没有人要。
func (a *App) requestState() {
	select {
	case a.stateKick <- struct{}{}:
	default:
	}
}

// stateLoop 合并状态推送。进程生命周期内常驻，随 logStop 退出。
//
// 合并策略是「等到下一次静默」：收到信号后先等 stateEmitMinInterval，把这段
// 时间里到达的请求全部吸收，再推一次。这既限住了频率，又保证最后一次变化
// 一定会被推出去（前沿触发会丢掉突变之后的最终状态）。
func (a *App) stateLoop() {
	for {
		select {
		case <-a.logStop:
			return
		case <-a.stateKick:
		}

		select {
		case <-a.logStop:
			return
		case <-time.After(stateEmitMinInterval):
		}

		// 把等待期间攒下的信号取走：它们已经由下面这次推送覆盖。
		select {
		case <-a.stateKick:
		default:
		}

		a.emitState()
	}
}

func (a *App) emitNotice(msg string) {
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "notice", msg)
}

// diffHint 给出两份配置的第一处差异，用于日志。
//
// 只在排查时用，所以刻意保持简单：逐行比对，报第一处不同。
// 配置只有几十行，这个开销可以忽略。
func diffHint(prev, cur string) string {
	if prev == "" {
		return "首次写入"
	}
	pl := strings.Split(prev, "\n")
	cl := strings.Split(cur, "\n")

	n := len(pl)
	if len(cl) < n {
		n = len(cl)
	}
	for i := 0; i < n; i++ {
		if pl[i] != cl[i] {
			return fmt.Sprintf("第 %d 行 %q → %q", i+1, shortLine(pl[i]), shortLine(cl[i]))
		}
	}
	if len(pl) != len(cl) {
		return fmt.Sprintf("行数 %d → %d", len(pl), len(cl))
	}
	// 逐行相同却没判等，说明差异在行分隔符或首尾空白上。
	return "逐行一致，差异在空白字符"
}

// Refresh 手工同步（界面上的「立即同步」）。
//
// 与后台同步走同一条路径，区别只有一点：手工触发时把错误直接返回给界面，
// 让用户看到「为什么没同步上」，而不是悄悄失败。
func (a *App) Refresh() (State, error) {
	// 与后台自动同步走完全相同的路径，区别只有一点：手工触发时
	// 把错误直接返回给界面，让用户看到「为什么没同步上」，
	// 而不是像后台那样只留一个低调的提示。
	gen := a.currentAuthGen()
	_, err := a.syncLocked()
	if err != nil {
		// 同步期间账号已切换时，这个错误属于旧账号，不能写进新账号的
		// SyncErr；错误仍要返回给触发者（界面），但状态不再发布。
		if a.authGenCurrent(gen) {
			a.setSyncErr(err)
			a.emitState()
		}
		return a.GetState(), err
	}
	if !a.authGenCurrent(gen) {
		return a.GetState(), nil
	}
	state := a.GetState()
	a.emitState()
	return state, nil
}

// recordTunnelErr 记下一条隧道的 frpc 错误（从原始输出行里取）。
// recordTunnelErr 记下一条隧道的错误说明，返回**错误原文是否变化**。
//
// 返回值给调用方决定要不要推状态：同样的错误重复刷屏时，状态里显示的东西
// 一个字都没变，推了只是白白让前端重建一次视图。
func (a *App) recordTunnelErr(id uint, line string) bool {
	return a.recordTunnelErrMsg(id, frpc.StripLogPrefix(line))
}

// currentAuthGen 读取当前账号代次。
//
// 异步任务（启动后的后台同步、退出回调、手动操作后的补充同步）在开始前
// 记下它，执行前再比对：期间发生登出/重新接入时，旧任务必须整段放弃，
// 否则它会把上一个账号的结论写进新账号的状态。
func (a *App) currentAuthGen() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authGeneration
}

// authGenCurrent 报告给定账号代次是否仍是当前代次。
func (a *App) authGenCurrent(gen uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authGeneration == gen
}

// setTunnelRegistered 标记某条隧道的代理是否已注册成功。
func (a *App) setTunnelRegistered(id uint, up bool) {
	a.setTunnelRegisteredGen(id, 0, up)
}

func (a *App) setTunnelRegisteredGen(id uint, gen uint64, up bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return
	}
	if a.registered == nil {
		a.registered = map[uint]bool{}
	}
	if a.registeredAt == nil {
		a.registeredAt = map[uint]time.Time{}
	}
	if up {
		a.registered[id] = true
		a.registeredAt[id] = time.Now()
		// 连上了就不再是「等待中」：清掉起点，避免下次掉线时显示一个
		// 从很久以前算起的等待时长。
		delete(a.connectAt, id)
		return
	}
	delete(a.registered, id)
	delete(a.registeredAt, id)
}

// markConnectStart 记录某条隧道「本次连接从什么时候开始」。
//
// 用于长时间连不上的诊断：frpc 进程活着、既没成功也没报错时，界面只能显示
// 「连接中」——用户不知道是刚起步还是已经卡了十分钟。记下起点后，界面可以
// 显示已等待时长，并在超过阈值时提示去看日志。
func (a *App) markConnectStart(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectAt == nil {
		a.connectAt = map[uint]time.Time{}
	}
	a.connectAt[id] = time.Now()
}

// clearConnectStart 撤销某条隧道的「等待中」起点。
//
// 用在「起点已经记下、但这次连接根本没起来」的路径上（启动失败、隧道被删、
// 退出登录）：留着的话，界面会显示一段并不存在的等待时长。
func (a *App) clearConnectStart(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.connectAt, id)
}

// markReconnectStart 记录「曾经连上、现在又断开」的等待起点。
//
// 与 markConnectStart 的区别是不覆盖已有起点：这条路径每轮同步都会走一次，
// 覆盖的话计时会永远停在「刚等了几秒」，反而看不出已经卡了多久。
func (a *App) markReconnectStart(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectAt == nil {
		a.connectAt = map[uint]time.Time{}
	}
	if _, ok := a.connectAt[id]; ok {
		return
	}
	a.connectAt[id] = time.Now()
}

// markStartGeneration 记下「这条隧道的进程此刻是在哪个账号代次下拉起的」。
//
// 必须与 authGeneration 在同一把锁内取，且要在 mgr.Start **之前**调用：
// 记下的必须是「启动那一刻的账号」，而不是「回调到来时的账号」。放在
// Start 之后的话，中间恰好完成一次退出登录，记录的就是新账号——那个
// 迟到的回调会被当成新账号的，正好放它去污染新账号的状态。
func (a *App) markStartGeneration(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.startGen == nil {
		a.startGen = map[uint]uint64{}
	}
	a.startGen[id] = a.authGeneration
}

// managerGenerationCurrentLocked 必须在 a.mu 内调用。
// 它把 Manager 的代次校验前移到状态写入的同一临界区。
func (a *App) managerGenerationCurrentLocked(id uint, gen uint64) bool {
	if gen == 0 || a.mgr == nil {
		return gen == 0
	}
	return a.mgr.Current(id, gen)
}

// startGeneration 返回这条隧道记录的启动代次，以及它是否属于当前账号。
//
// 没有记录时返回 (0, false)：说明这条隧道的启动记账已被清掉（退出登录或
// 隧道被删），此刻**无法证明**进程属于当前账号。宁可漏掉一次状态清理
// ——下一轮同步会据实对账——也不要让它去改新账号的运行态。
//
// 这里刻意不提供「删掉自己那条记录」的写法：记账的值就是账号代次，
// 同一账号下重复启动得到的是同一个值，回调无法分辨手上的记录是本次启动
// 留下的还是下一次启动刚写的。删错一次就等于把下一次启动的记录抹掉，
// 它的回调从此变成「查无记录」、永远被跳过。而留着这个条目的代价只有
// 每个隧道 id 一个 uint64：隧道被服务端删除时由 pruneTunnelState 清、
// 退出登录时由 resetPerAccountState 清，不存在随进程寿命增长的泄漏。
func (a *App) startGeneration(id uint) (uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	gen, ok := a.startGen[id]
	if !ok {
		return 0, false
	}
	return gen, gen == a.authGeneration
}

// registeredGrace 是本机「已注册」标记不被服务端结论推翻的宽限期。
//
// 服务端 online 的延迟上限约 50 秒（采集 30 秒 + 同步 20 秒），
// 留到 90 秒：小于它就把刚连上的隧道判成离线（界面一闪一闪），
// 大于它则「服务端早就说离线、本地还显示运行中」会持续过久。
const registeredGrace = 90 * time.Second

// calibrateRegistered 用服务端的事实校准本机的「已注册」标记。
//
// 这条路径解决的是「界面长期显示运行中，实际早就掉线」：
//
//	frpc 报告 start proxy success → 本地标记置位；
//	之后 frps 重启 / 代理被踢掉 / 连接被切断，frpc 进入重连循环，
//	进程一直活着 → 本地标记永远为真，而服务端的 online 早已是 false。
//
// 宽限期内的服务端 false 不采信（那时它多半还没采到），过了宽限期则采信：
// 清掉标记，并记下原因，让隧道行显示的是「服务端确认离线」而不是一片沉默。
func (a *App) calibrateRegistered(id uint, serverOnline bool) {
	a.mu.Lock()
	if !a.registered[id] {
		a.mu.Unlock()
		return
	}
	if serverOnline {
		// 服务端认了，顺带把时间戳刷新：下一次掉线要重新算宽限期。
		if a.registeredAt != nil {
			a.registeredAt[id] = time.Now()
		}
		a.mu.Unlock()
		return
	}
	at, ok := a.registeredAt[id]
	a.mu.Unlock()

	if ok && time.Since(at) < registeredGrace {
		return
	}

	// 只有这次校准读取到的注册时间仍然是当前时间戳时才清除。
	// 等待宽限期期间若新进程重新注册，registeredAt 已被更新，旧校准不能
	// 把新进程的在线状态抹掉。
	a.mu.Lock()
	stillSame := a.registered[id] && a.registeredAt[id] == at
	if stillSame {
		delete(a.registered, id)
		delete(a.registeredAt, id)
	}
	a.mu.Unlock()
	if !stillSame {
		return
	}
	// 从这里开始重新计时：frpc 进程还在，正在自己重连。没有起点的话，
	// 界面只会显示「连接中」，用户分不清是刚掉线还是已经卡了很久。
	a.markReconnectStart(id)
	// 记原因，但不升级成「启动失败」：进程还在，frpc 自己会重连，
	// 进退避只会让它更晚恢复。
	if a.recordTunnelErrMsg(id, "服务端报告该隧道已离线（本机 frpc 仍在运行，可能正在重连）") {
		a.emitStateThrottled(id)
	}
}

// emitStateThrottled 推一次状态，但同一隧道 1 秒内只推一次。
//
// 限频只在**错误洪峰**这条路径上用：正常的开关、同步、注册成功都必须立即
// 反映到界面。丢掉的那一次不会让界面停在错误状态上——错误原文变化时必然会
// 推（那是用户要看的信息），后续同步（≤20 秒）也会带上最新状态。
func (a *App) emitStateThrottled(id uint) {
	a.mu.Lock()
	if a.errEmitAt == nil {
		a.errEmitAt = map[uint]time.Time{}
	}
	now := time.Now()
	if last, ok := a.errEmitAt[id]; ok && now.Sub(last) < time.Second {
		a.mu.Unlock()
		return
	}
	a.errEmitAt[id] = now
	a.mu.Unlock()

	a.emitState()
}

// recordTunnelErrMsg 记下一条隧道的错误说明。
//
// 除了 frpc 自己打印的错误，客户端**自己**发现的失败也要记（拉配置失败、
// 进程起不来）：那些失败同样让这条隧道连不上，只写进日志的话，
// 界面上的隧道行仍然什么原因都不显示。
func (a *App) recordTunnelErrMsg(id uint, msg string) bool {
	return a.recordTunnelErrMsgGen(id, 0, msg)
}

func (a *App) recordTunnelErrMsgGen(id uint, gen uint64, msg string) bool {
	return a.recordTunnelErrMsgAcct(id, a.captureEpoch(), gen, msg)
}

// recordTunnelErrMsgAcct 记下错误说明，并核对它所属的账号。
//
// 账号校验必须在 a.mu 内、与写入同源：分开两次快照的话，登出可以恰好
// 落在两次之间，于是上一个账号的失败原因被写进新账号的界面。
func (a *App) recordTunnelErrMsgAcct(id uint, acct accountEpoch, gen uint64, msg string) bool {
	msg = clampStatusText(strings.TrimSpace(msg))
	if msg == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return false
	}
	if acct.known() && a.accountEpochLocked() != acct {
		return false
	}
	if a.tunnelErrs == nil {
		a.tunnelErrs = map[uint]tunnelErr{}
	}
	prev, ok := a.tunnelErrs[id]
	// 时间戳每次都更新（它表示「最近一次出现」），但只有原文变化才算变化。
	a.tunnelErrs[id] = tunnelErr{msg: msg, at: time.Now()}
	return !ok || prev.msg != msg
}

// clearTunnelErr 清掉一条隧道的错误记录。
//
// 连上之后必须清：否则界面会一直挂着一次已经过去的失败，
// 用户会以为现在还是坏的。
func (a *App) clearTunnelErr(id uint) {
	a.clearTunnelErrGen(id, 0)
}

func (a *App) clearTunnelErrGen(id uint, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return
	}
	delete(a.tunnelErrs, id)
}

// emitTunnelReadyEpoch 在 frpc 报告代理启动成功后，补上「现在可以用这个地址了」。
//
// 地址必须紧跟在「启动成功」之后：用户要的就是「该把哪个地址发给朋友」，
// 让他自己去列表里再找一遍完全是多余的。
//
// 调用方是日志回调：那里的账号代次来自「启动这条进程时的账号」，
// 必须原样传下来，而不是在这里重新取一次当前的账号——重新取会把上一账号
// 进程的成功说明写进新账号的日志。
func (a *App) emitTunnelReadyEpoch(acct accountEpoch, id uint, name string) {
	a.mu.RLock()
	addr := ""
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			addr = a.tunnels[i].PublicAddr
			break
		}
	}
	a.mu.RUnlock()

	a.emitTunnelLogEpoch(acct, name, "隧道启动成功")
	if addr != "" {
		a.emitTunnelLogEpoch(acct, name, "使用 >>"+addr+"<< 连接你的隧道")
	}
}
