package main

import (
	"fmt"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

const maxStatusTextRunes = 400

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

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
	seq, gen, st := a.snapshotForEmit()
	st.StateSeq = seq
	st.AuthGen = gen
	wailsruntime.EventsEmit(a.ctx, "state", st)
}

func (a *App) snapshotForEmit() (seq, gen uint64, st State) {
	logEpoch := a.currentLogEpoch()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.stateSeq++
	seq = a.stateSeq
	gen = a.authGeneration
	st = a.getStateLocked(logEpoch)
	return seq, gen, st
}

const stateEmitMinInterval = 100 * time.Millisecond

func (a *App) requestState() {
	select {
	case a.stateKick <- struct{}{}:
	default:
	}
}

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
	return "逐行一致，差异在空白字符"
}

func (a *App) Refresh() (State, error) {
	gen := a.currentAuthGen()
	_, err := a.syncLocked()
	if err != nil {
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

func (a *App) recordTunnelErr(id uint, line string) bool {
	return a.recordTunnelErrMsg(id, frpc.StripLogPrefix(line))
}

func (a *App) currentAuthGen() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authGeneration
}

func (a *App) authGenCurrent(gen uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.authGeneration == gen
}

func (a *App) setTunnelRegistered(id uint, up bool) {
	a.setTunnelRegisteredGen(id, 0, up)
}

func (a *App) setTunnelRegisteredGen(id uint, gen uint64, up bool) {
	a.setTunnelRegisteredAcct(id, noEpoch, gen, up)
}

func (a *App) setTunnelRegisteredAcct(id uint, acct accountEpoch, gen uint64, up bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return
	}
	if !a.accountStillLocked(acct) {
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
		delete(a.connectAt, id)
		return
	}
	delete(a.registered, id)
	delete(a.registeredAt, id)
}

func (a *App) markConnectStart(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connectAt == nil {
		a.connectAt = map[uint]time.Time{}
	}
	a.connectAt[id] = time.Now()
}

func (a *App) clearConnectStart(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.connectAt, id)
}

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

func (a *App) markStartGeneration(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.startGen == nil {
		a.startGen = map[uint]uint64{}
	}
	a.startGen[id] = a.authGeneration
	if a.mgr != nil {
		a.mgr.SetTunnelAccount(id, a.authGeneration)
	}
}

func (a *App) managerGenerationCurrentLocked(id uint, gen uint64) bool {
	if gen == 0 || a.mgr == nil {
		return gen == 0
	}
	return a.mgr.Current(id, gen)
}

func (a *App) startGeneration(id uint) (uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	gen, ok := a.startGen[id]
	if !ok {
		return 0, false
	}
	return gen, gen == a.authGeneration
}

const registeredGrace = 90 * time.Second

func (a *App) calibrateRegistered(id uint, serverOnline bool) {
	a.mu.Lock()
	if !a.registered[id] {
		a.mu.Unlock()
		return
	}
	if serverOnline {
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
	a.markReconnectStart(id)
	if a.recordTunnelErrMsg(id, "服务端报告该隧道已离线（本机 frpc 仍在运行，可能正在重连）") {
		a.emitStateThrottled(id)
	}
}

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

func (a *App) recordTunnelErrMsg(id uint, msg string) bool {
	return a.recordTunnelErrMsgGen(id, 0, msg)
}

func (a *App) recordTunnelErrMsgGen(id uint, gen uint64, msg string) bool {
	return a.recordTunnelErrMsgAcct(id, a.captureEpoch(), gen, msg)
}

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
	a.tunnelErrs[id] = tunnelErr{msg: msg, at: time.Now()}
	return !ok || prev.msg != msg
}

func (a *App) clearTunnelErr(id uint) {
	a.clearTunnelErrGen(id, 0)
}

func (a *App) clearTunnelErrGen(id uint, gen uint64) {
	a.clearTunnelErrAcct(id, noEpoch, gen)
}

func (a *App) clearTunnelErrAcct(id uint, acct accountEpoch, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return
	}
	if !a.accountStillLocked(acct) {
		return
	}
	delete(a.tunnelErrs, id)
}

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
