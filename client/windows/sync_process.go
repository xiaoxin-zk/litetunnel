package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errSyncDeadline = errors.New("本轮同步已超时，该隧道未写入配置也未启动")

func (a *App) writeAndStart(ctx context.Context, t TunnelVO, cfgText string) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}
	path, err := frpcConfigPath(t.ID)
	if err != nil {
		return asConfigStage(err)
	}
	if err := writeFrpcConfig(t.ID, cfgText); err != nil {
		return asConfigStage(err)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}

	a.emitTunnelLog(t.Name, "开始加载隧道配置："+path)

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}

	a.clearRetry(t.ID)
	a.setTunnelRegistered(t.ID, false)

	a.markConnectStart(t.ID)
	a.markStartGeneration(t.ID)
	if err := a.mgr.Start(t.ID, t.Name, path); err != nil {
		a.clearConnectStart(t.ID)
		return err
	}

	a.mu.Lock()
	a.applied[t.ID] = cfgText
	a.mu.Unlock()
	a.setConfigRev(t.ID, t.ConfigRev)
	return nil
}

func (a *App) setConfigRev(id uint, rev string) {
	a.mu.Lock()
	if rev == "" {
		delete(a.cfgRev, id)
	} else {
		a.cfgRev[id] = rev
	}
	a.mu.Unlock()
}

type configStageError struct{ err error }

func (e configStageError) Error() string { return e.err.Error() }
func (e configStageError) Unwrap() error { return e.err }

func asConfigStage(err error) error {
	if err == nil {
		return nil
	}
	return configStageError{err: err}
}

func isConfigStage(err error) bool {
	var e configStageError
	return errors.As(err, &e)
}

func (a *App) startTunnelProcess(ctx context.Context, t TunnelVO) error {
	if a.mgr.Running(t.ID) {
		return nil
	}
	if !a.mgr.Available() {
		return asConfigStage(errors.New("未找到 frpc 可执行文件，请将 frpc.exe 放到程序同目录"))
	}
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return asConfigStage(err)
	}
	cfgText, servedRev, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
	if err != nil {
		return asConfigStage(err)
	}
	if cfgText == "" {
		return asConfigStage(errors.New("服务端未返回该隧道的配置"))
	}
	t.ConfigRev = servedRev
	a.clearStopIntent(t.ID)
	err = a.writeAndStart(ctx, t, cfgText)
	if errors.Is(err, errSyncDeadline) {
		return ctx.Err()
	}
	return err
}

func (a *App) stopTunnelProcess(t TunnelVO) error {
	a.emitTunnelLog(t.Name, "隧道已断开")
	a.setTunnelRegistered(t.ID, false)
	gen, ok := a.mgr.Gen(t.ID)
	if !ok {
		return nil
	}
	a.markStopIntent(t.ID, gen)
	err := a.mgr.Stop(t.ID)
	if err != nil {
		a.clearStopIntentGen(t.ID, gen)
	}
	return err
}

func (a *App) markStopIntent(id uint, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopIntents == nil {
		a.stopIntents = map[uint]uint64{}
	}
	a.stopIntents[id] = gen
}

func (a *App) clearStopIntent(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.stopIntents, id)
}

func (a *App) clearStopIntentGen(id uint, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopIntents[id] == gen {
		delete(a.stopIntents, id)
	}
}

func (a *App) consumeStopIntent(id uint, gen uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	want, ok := a.stopIntents[id]
	if !ok {
		return false
	}
	if gen != 0 && want != gen {
		return false
	}
	delete(a.stopIntents, id)
	return true
}

func retryDelay(attempts int) time.Duration {
	const maxDelay = 5 * time.Minute
	if attempts < 1 {
		attempts = 1
	}
	d := 30 * time.Second
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= maxDelay {
			return maxDelay
		}
	}
	return d
}

func (a *App) retryAllowed(id uint) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	st := a.retries[id]
	return st == nil || time.Now().After(st.nextAt)
}

func (a *App) noteStartFailure(id uint, name, reason string) {
	a.noteStartFailureGen(id, 0, name, reason)
}

func (a *App) noteStartFailureGen(id uint, gen uint64, name, reason string) {
	a.noteStartFailureAcct(id, a.captureEpoch(), gen, name, reason)
}

func (a *App) noteStartFailureAcct(id uint, acct accountEpoch, gen uint64, name, reason string) {
	a.mu.Lock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		a.mu.Unlock()
		return
	}
	if acct.known() && a.accountEpochLocked() != acct {
		a.mu.Unlock()
		return
	}
	if a.retries == nil {
		a.retries = map[uint]*retryState{}
	}
	st := a.retries[id]
	if st == nil {
		st = &retryState{}
		a.retries[id] = st
	}
	st.attempts++
	delay := retryDelay(st.attempts)
	st.nextAt = time.Now().Add(delay)
	attempts := st.attempts
	a.mu.Unlock()

	a.emitTunnelLogEpoch(acct, name, fmt.Sprintf("%s（第 %d 次失败，%s 后重试）",
		reason, attempts, delay.Round(time.Second)))
}

func (a *App) clearRetry(id uint) {
	a.clearRetryGen(id, 0)
}

func (a *App) clearRetryGen(id uint, gen uint64) {
	a.clearRetryAcct(id, noEpoch, gen)
}

func (a *App) clearRetryAcct(id uint, acct accountEpoch, gen uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != 0 && !a.managerGenerationCurrentLocked(id, gen) {
		return
	}
	if !a.accountStillLocked(acct) {
		return
	}
	delete(a.retries, id)
}

func writeFrpcConfig(tunnelID uint, text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("服务端返回的配置为空")
	}
	path, err := frpcConfigPath(tunnelID)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("写入客户端配置失败: %w", err)
	}
	return nil
}
