package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// errTunnelSyncPartial 表示面板可达，只是部分隧道同步失败。
// 这类失败要展示给用户，但不触发全局退避：健康隧道的变更仍需按 20 秒节奏同步。
var errTunnelSyncPartial = errors.New("部分隧道同步失败")

func (a *App) applySyncData(ctx context.Context, data *clientInfoData, seq uint64) (changed bool, err error) {
	if seq <= a.appliedSyncSeq {
		return false, nil
	}
	consumed := false
	defer func() {
		if consumed {
			a.appliedSyncSeq = seq
		}
	}()

	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if base == "" || apiKey == "" {
		return false, errors.New(a.baseReason())
	}

	a.mu.Lock()
	a.tunnels = data.Tunnels
	a.gatewayHost = data.ServerAddr
	a.gatewayPort = data.ServerPort
	a.frontendURL = data.FrontendURL
	a.tunnelDomain = data.TunnelDomain
	a.trafficUsed = data.TrafficUsed
	a.trafficQuota = data.TrafficQuota
	a.exceeded = data.Exceeded
	a.group = data.Group
	a.paymentEnabled = data.PaymentEnabled
	a.balanceCents = data.BalanceCents
	if data.Username != "" {
		a.username = data.Username
	}
	if a.tunnels == nil {
		a.tunnels = []TunnelVO{}
	}
	a.lastSyncAt = time.Now()
	a.syncErr = ""
	a.mu.Unlock()

	tunnels := make([]TunnelVO, len(data.Tunnels))
	copy(tunnels, data.Tunnels)

	alive := make(map[uint]bool, len(tunnels))
	for _, t := range tunnels {
		alive[t.ID] = true
	}
	for _, id := range a.mgr.RunningIDs() {
		if alive[id] {
			continue
		}
		name := a.mgr.TunnelName(id)
		if name == "" {
			name = fmt.Sprintf("#%d", id)
		}
		a.emitTunnelLog(name, "隧道已不存在，正在断开")
		if err := a.mgr.Stop(id); err != nil {
			return changed, err
		}
		changed = true
	}
	a.pruneTunnelState(alive)

	a.cleanupStaleConfigs(alive)

	var failures []string

	recordFailure := func(t TunnelVO, msg string) {
		a.emitTunnelLog(t.Name, msg)
		a.recordTunnelErrMsg(t.ID, msg)
		failures = append(failures, t.Name+"："+msg)
	}
	failSync := func(t TunnelVO, msg string) {
		recordFailure(t, msg)
	}
	failStart := func(t TunnelVO, msg string) {
		recordFailure(t, msg)
		a.noteStartFailure(t.ID, t.Name, msg)
	}

	var pending []TunnelVO
	for _, t := range tunnels {
		a.calibrateRegistered(t.ID, t.Online)

		if t.Status != tunnelStatusActive {
			a.clearRetry(t.ID)
			if a.mgr.Running(t.ID) {
				if err := a.stopTunnelProcess(t); err != nil {
					return changed, err
				}
				changed = true
			}
			continue
		}

		if !a.mgr.Running(t.ID) && !a.retryAllowed(t.ID) {
			continue
		}
		pending = append(pending, t)
	}

	rot := 0
	if n := len(pending); n > 1 {
		rot = a.syncStart % n
		if rot > 0 {
			ordered := make([]TunnelVO, 0, n)
			ordered = append(ordered, pending[rot:]...)
			ordered = append(ordered, pending[:rot]...)
			pending = ordered
		}
	}

	type cachedCfg struct {
		t    TunnelVO
		text string
	}
	var (
		cached    []cachedCfg
		needFetch []TunnelVO
		fetchPos  []int
	)
	for i, t := range pending {
		if text, ok := a.cachedConfig(t.ID, t.ConfigRev); ok {
			cached = append(cached, cachedCfg{t: t, text: text})
			continue
		}
		needFetch = append(needFetch, t)
		fetchPos = append(fetchPos, i)
	}

	applyCfg := func(t TunnelVO, cfgText, servedRev string, cfgErr error) (settled bool) {
		if ctx.Err() != nil {
			return false
		}
		if cfgErr != nil {
			failSync(t, "拉取配置失败："+cfgErr.Error())
			return true
		}
		if cfgText == "" {
			failSync(t, "服务端未返回该隧道的配置")
			return true
		}

		t.ConfigRev = servedRev

		prev := a.appliedConfigOf(t.ID)
		cfgChanged := cfgText != prev

		if !cfgChanged {
			a.setConfigRev(t.ID, t.ConfigRev)
		} else {
			a.setConfigRev(t.ID, "")
		}

		switch {
		case !a.mgr.Running(t.ID):
			if err := a.writeAndStart(ctx, t, cfgText); err != nil {
				if errors.Is(err, errSyncDeadline) {
					return false
				}
				if isConfigStage(err) {
					failSync(t, "准备配置失败："+err.Error())
					return true
				}
				failStart(t, "启动失败："+err.Error())
				return true
			}
			changed = true
		case cfgChanged:
			if ctx.Err() != nil {
				return false
			}
			a.emitTunnelLog(t.Name, "配置有变化（"+diffHint(prev, cfgText)+"），正在重连")
			if err := a.mgr.Stop(t.ID); err != nil {
				failStart(t, "重连失败：停止旧进程失败："+err.Error())
				return true
			}
			if err := a.writeAndStart(ctx, t, cfgText); err != nil {
				if errors.Is(err, errSyncDeadline) {
					return false
				}
				if isConfigStage(err) {
					failSync(t, "准备配置失败："+err.Error())
					return true
				}
				failStart(t, "重连失败："+err.Error())
				return true
			}
			changed = true
		}
		return true
	}

	round := newSyncRound(pending, fetchPos)

	results, dispatched := a.streamTunnelConfigs(ctx, base, apiKey, needFetch)
	for res := range results {
		if applyCfg(res.tunnel, res.text, res.rev, res.err) {
			round.settle(res.tunnel.ID)
		}
	}
	for _, c := range cached {
		if applyCfg(c.t, c.text, c.t.ConfigRev, nil) {
			round.settle(c.t.ID)
		}
	}
	if n := len(pending); n > 0 {
		round.setDispatched(int(dispatched.Load()))
		a.syncStart = round.nextStart(rot, n)
	}

	if ctx.Err() != nil {
		roundErr := fmt.Errorf("本轮同步超时（超过 %s），未处理的隧道将在下一轮优先重试", syncRoundTimeout)
		if len(failures) > 0 {
			roundErr = fmt.Errorf("%w；另有 %d 条隧道同步失败", roundErr, len(failures))
		}
		return changed, roundErr
	}

	consumed = true
	if len(failures) > 0 {
		detail := failures[0]
		if len(failures) > 1 {
			detail = fmt.Sprintf("%s 等 %d 条", failures[0], len(failures))
		}
		// 单条隧道失败不代表面板不可用：标记成 partial，调度层不据此退避。
		return changed, fmt.Errorf("%w：%d 条隧道同步失败：%s", errTunnelSyncPartial, len(failures), detail)
	}
	return changed, nil
}
