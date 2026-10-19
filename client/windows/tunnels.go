package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/client/internal/localsvc"
)

const (
	tunnelStatusActive   = "active"
	tunnelStatusDisabled = "disabled"
)

func (a *App) ListLocalServices() ([]localsvc.Service, error) {
	return localsvc.List()
}

func (a *App) CreateTunnel(name, tunnelType, localIP string, localPort, remotePort int, subdomain string) (State, error) {
	ctx, cancel := a.newMutateContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return a.GetState(), err
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}

	payload, err := json.Marshal(map[string]any{
		"name":        strings.TrimSpace(name),
		"type":        strings.TrimSpace(tunnelType),
		"local_ip":    strings.TrimSpace(localIP),
		"local_port":  localPort,
		"remote_port": remotePort,
		"subdomain":   strings.TrimSpace(subdomain),
	})
	if err != nil {
		return a.GetState(), err
	}
	if _, err := a.do(ctx, http.MethodPost, base+"/api/user/tunnels", apiKey, payload); err != nil {
		return a.GetState(), err
	}
	state := a.syncAndStateCtx(ctx)
	return state, nil
}

type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

type BatchResult struct {
	Message  string         `json:"message"`
	Failures []BatchFailure `json:"failures"`
}

func (a *App) CreateTunnelsBatch(namePrefix, tunnelType, localIP string, ports []int) (BatchResult, State, error) {
	ctx, cancel := a.newMutateContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return BatchResult{}, a.GetState(), err
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	payload, err := json.Marshal(map[string]any{
		"name_prefix": strings.TrimSpace(namePrefix),
		"type":        strings.TrimSpace(tunnelType),
		"local_ip":    strings.TrimSpace(localIP),
		"ports":       ports,
	})
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	raw, err := a.do(ctx, http.MethodPost, base+"/api/user/tunnels/batch", apiKey, payload)
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	var out BatchResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return BatchResult{}, a.GetState(), err
	}
	out.Message = clampStatusText(out.Message)
	for i := range out.Failures {
		out.Failures[i].Reason = clampStatusText(out.Failures[i].Reason)
	}

	state := a.syncAndStateCtx(ctx)
	return out, state, nil
}

func (a *App) DeleteTunnel(id uint) (State, error) {
	ctx, cancel := a.newMutateContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return a.GetState(), err
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d", base, id)
	if _, err := a.do(ctx, http.MethodDelete, endpoint, apiKey, nil); err != nil {
		return a.GetState(), err
	}

	if err := a.mgr.Stop(id); err != nil {
		msg := "隧道已在服务端删除，但本地 frpc 进程停止失败，配置文件暂未清理：" + err.Error()
		a.emitNotice(msg)
		return a.GetState(), errors.New(msg)
	}

	a.clearTunnelErr(id)
	a.clearRetry(id)

	state := a.syncAndStateCtx(ctx)
	if err := removeFrpcConfig(id); err != nil {
		a.emitNotice("隧道已删除，但本地配置文件删除失败（其中含接入密钥）：" + err.Error())
		return a.GetState(), err
	}
	return state, nil
}

func (a *App) StartTunnel(id uint) (State, error) {
	ctx, cancel := a.newManualContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return a.GetState(), describeManualErr(err)
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusActive {
		a.emitTunnelLog(t.Name, "正在启用（提交服务端状态）…")
		if err := a.setTunnelStatus(ctx, base, apiKey, id, tunnelStatusActive); err != nil {
			return a.GetState(), describeManualErr(err)
		}
		a.applyLocalStatus(id, tunnelStatusActive)
		if nt, ok := a.findTunnel(id); ok {
			t = nt
		}
	}
	a.emitTunnelLog(t.Name, "正在拉取配置并启动 frpc…")
	if err := a.startTunnelProcess(ctx, t); err != nil {
		if !isConfigStage(err) {
			a.noteStartFailure(id, t.Name, "启动失败："+err.Error())
		}
		return a.GetState(), describeManualErr(err)
	}

	state := a.GetState()
	a.emitState()
	gen := a.currentAuthGen()
	go func() {
		if err := a.lockSync(a.rootContext()); err != nil {
			return
		}
		defer a.unlockSync()
		if !a.authGenCurrent(gen) {
			return
		}
		a.syncAndState()
	}()
	return state, nil
}

func (a *App) StopTunnel(id uint) (State, error) {
	ctx, cancel := a.newManualContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return a.GetState(), describeManualErr(err)
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusDisabled {
		a.emitTunnelLog(t.Name, "正在停用（提交服务端状态）…")
		if err := a.setTunnelStatus(ctx, base, apiKey, id, tunnelStatusDisabled); err != nil {
			return a.GetState(), describeManualErr(err)
		}
		a.applyLocalStatus(id, tunnelStatusDisabled)
	}
	if err := a.stopTunnelProcess(t); err != nil {
		return a.GetState(), err
	}

	state := a.GetState()
	a.emitState()
	gen := a.currentAuthGen()
	go func() {
		if err := a.lockSync(a.rootContext()); err != nil {
			return
		}
		defer a.unlockSync()
		if !a.authGenCurrent(gen) {
			return
		}
		a.syncAndState()
	}()
	return state, nil
}

func (a *App) applyLocalStatus(id uint, status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			a.tunnels[i].Status = status
			return
		}
	}
}

func (a *App) syncAndState() State {
	return a.syncAndStateCtx(a.rootContext())
}

func (a *App) syncAndStateCtx(parent context.Context) State {
	if _, err := a.applySyncCtx(parent); err != nil {
		a.setSyncErr(err)
	}
	state := a.GetState()
	a.emitState()
	return state
}

func (a *App) setTunnelStatus(ctx context.Context, base, apiKey string, id uint, status string) error {
	payload, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d/status", base, id)
	_, err = a.do(ctx, http.MethodPost, endpoint, apiKey, payload)
	return err
}

const manualOpTimeout = 30 * time.Second

func (a *App) newManualContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.rootContext(), manualOpTimeout)
}

func (a *App) newMutateContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.rootContext(), syncRoundTimeout)
}

func describeManualErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("操作超时（超过 %s），请检查网络后重试", manualOpTimeout)
	}
	return err
}

func (a *App) findTunnel(id uint) (TunnelVO, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			return a.tunnels[i], true
		}
	}
	return TunnelVO{}, false
}

func (a *App) Redeem(code string) (string, State, error) {
	ctx, cancel := a.newMutateContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return "", a.GetState(), err
	}
	defer a.unlockSync()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return "", a.GetState(), err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", a.GetState(), errors.New("请输入兑换码")
	}

	payload, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return "", a.GetState(), err
	}
	raw, err := a.do(ctx, http.MethodPost, base+"/api/user/redeem", apiKey, payload)
	if err != nil {
		return "", a.GetState(), err
	}

	var out struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Message == "" {
		out.Message = "兑换成功"
	}
	out.Message = clampStatusText(out.Message)

	state := a.syncAndStateCtx(ctx)
	return out.Message, state, nil
}
