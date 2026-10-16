package main

import (
	"fmt"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

func (a *App) setSyncErr(err error) {
	a.mu.Lock()
	a.syncErr = err.Error()
	a.mu.Unlock()
}

func (a *App) emitState() {
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "state", a.GetState())
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
	_, err := a.syncLocked()
	if err != nil {
		a.setSyncErr(err)
		a.emitState()
		return a.GetState(), err
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

// setTunnelRegistered 标记某条隧道的代理是否已注册成功。
func (a *App) setTunnelRegistered(id uint, up bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registered == nil {
		a.registered = map[uint]bool{}
	}
	if a.registeredAt == nil {
		a.registeredAt = map[uint]time.Time{}
	}
	if up {
		a.registered[id] = true
		a.registeredAt[id] = time.Now()
		return
	}
	delete(a.registered, id)
	delete(a.registeredAt, id)
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

	a.setTunnelRegistered(id, false)
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
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
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
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tunnelErrs, id)
}

// emitTunnelReady 在 frpc 报告代理启动成功后，补上「现在可以用这个地址了」。
//
// 地址必须紧跟在「启动成功」之后：用户要的就是「该把哪个地址发给朋友」，
// 让他自己去列表里再找一遍完全是多余的。
func (a *App) emitTunnelReady(id uint, name string) {
	a.mu.RLock()
	addr := ""
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			addr = a.tunnels[i].PublicAddr
			break
		}
	}
	a.mu.RUnlock()

	a.emitTunnelLog(name, "隧道启动成功")
	if addr != "" {
		a.emitTunnelLog(name, "使用 >>"+addr+"<< 连接你的隧道")
	}
}
