package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type clientInfo struct {
	ServerAddr   string `json:"server_addr"`
	ServerPort   int    `json:"server_port"`
	FrontendURL  string `json:"frontend_url"`
	User         string `json:"user"`
	TunnelDomain string `json:"tunnel_domain"`
}

type groupLimit struct {
	Name               string `json:"name"`
	MaxTunnels         int    `json:"max_tunnels"`
	AllowProtocols     string `json:"allow_protocols"`
	AllowCustomDomain  bool   `json:"allow_custom_domain"`
	BandwidthLimitStr  string `json:"bandwidth_limit_str"`
	HTTPSTunnelEnabled *bool  `json:"https_tunnel_enabled"`
	HTTPSEntry         string `json:"https_entry"`
	MaxPorts           int    `json:"max_ports"`
}

type clientInfoData struct {
	clientInfo
	Username       string      `json:"username"`
	Nickname       string      `json:"nickname"`
	Tunnels        []TunnelVO  `json:"tunnels"`
	TrafficUsed    int64       `json:"traffic_used"`
	TrafficQuota   int64       `json:"traffic_quota"`
	Exceeded       bool        `json:"exceeded"`
	TunnelTotal    int64       `json:"tunnel_total"`
	ListVersion    string      `json:"list_version,omitempty"`
	Group          *groupLimit `json:"group,omitempty"`
	BalanceCents   int64       `json:"balance_cents"`
	PaymentEnabled bool        `json:"payment_enabled"`
}

func (a *App) serverBase() string {
	if base := defaultServerURL(); base != "" {
		checked, err := checkServerURL(base, true)
		if err != nil {
			return ""
		}
		return checked
	}
	a.mu.RLock()
	raw := a.cfg.ServerURL
	a.mu.RUnlock()
	if raw == "" {
		return ""
	}
	checked, err := checkServerURL(raw, false)
	if err != nil {
		return ""
	}
	return checked
}

func (a *App) baseReason() string {
	if base := defaultServerURL(); base != "" {
		if _, err := checkServerURL(base, true); err != nil {
			return "客户端内置的服务器地址不可用：" + err.Error()
		}
		return "尚未接入，请先连接"
	}
	a.mu.RLock()
	raw := a.cfg.ServerURL
	a.mu.RUnlock()
	if raw != "" {
		if _, err := checkServerURL(raw, false); err != nil {
			return "已保存的服务器地址不可用：" + err.Error() + "。请退出登录后重新填写"
		}
	}
	return "尚未接入，请先连接"
}

func (a *App) isLoggedIn() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.username != ""
}

func (a *App) Connect(apiKey, serverURL string) (State, error) {
	a.mu.RLock()
	generation := a.authGeneration
	a.mu.RUnlock()
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return a.GetState(), errors.New("请填写 API Key")
	}
	if a.isLoggedIn() {
		return a.GetState(), errors.New("当前账号已接入，请先退出当前账号再重新接入")
	}

	base, err := a.resolveBase(serverURL)
	if err != nil {
		return a.GetState(), err
	}

	ctx, cancel := context.WithTimeout(a.rootContext(), syncRoundTimeout)
	defer cancel()
	info, err := a.fetchClientInfo(ctx, base, apiKey)
	if err != nil {
		return a.GetState(), err
	}
	seq := a.nextSyncSeq()

	username := info.Username
	if username == "" {
		username = info.Nickname
	}

	if err := a.lockSync(ctx); err != nil {
		return a.GetState(), err
	}
	defer a.unlockSync()
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if err := ctx.Err(); err != nil {
		return a.GetState(), err
	}
	a.mu.RLock()
	if generation != a.authGeneration {
		a.mu.RUnlock()
		return a.GetState(), errors.New("登录状态已变化，请重新接入")
	}
	var candidate Config
	if a.cfg != nil {
		candidate = *a.cfg
	}
	a.mu.RUnlock()
	candidate.APIKey = apiKey
	candidate.ServerURL = base
	if err := saveConfig(&candidate); err != nil {
		a.mu.Lock()
		a.lastError = "接入信息保存失败：" + err.Error()
		a.mu.Unlock()
		return a.GetState(), err
	}

	a.mu.Lock()
	if a.cfg == nil {
		a.cfg = &Config{}
	}
	a.cfg.APIKey = apiKey
	a.cfg.ServerURL = base
	a.username = username
	a.apiKeyMask = maskKey(apiKey)
	a.gatewayHost = info.ServerAddr
	a.gatewayPort = info.ServerPort
	a.frontendURL = info.FrontendURL
	a.tunnelDomain = info.TunnelDomain
	a.tunnels = info.Tunnels
	a.trafficUsed = info.TrafficUsed
	a.trafficQuota = info.TrafficQuota
	a.exceeded = info.Exceeded
	a.group = info.Group
	a.paymentEnabled = info.PaymentEnabled
	a.balanceCents = info.BalanceCents
	a.lastError = ""
	a.cfgErr = ""
	if a.tunnels == nil {
		a.tunnels = []TunnelVO{}
	}
	a.authGeneration++
	a.mu.Unlock()

	if _, err := a.syncWithDataLocked(ctx, info, seq); err != nil {
		a.setSyncErr(err)
	}
	return a.GetState(), nil
}

func (a *App) Logout() (State, error) {
	return a.logout(clearConfig, removeAllFrpcConfigs)
}

const logoutSyncWait = 10 * time.Second

const logoutCallbackWait = 3 * time.Second

func (a *App) logout(clearMain, clearTunnels func() error) (State, error) {
	waitCtx, waitCancel := context.WithTimeout(a.rootContext(), logoutSyncWait)
	defer waitCancel()
	if err := a.lockSync(waitCtx); err != nil {
		return a.GetState(), errors.New("正在同步隧道，请稍后再退出登录")
	}
	defer a.unlockSync()

	if err := a.mgr.StopAll(); err != nil {
		return a.GetState(), fmt.Errorf("停止隧道失败，未退出登录: %w", err)
	}

	if !a.mgr.WaitCallbacks(logoutCallbackWait) {
		log.Printf("[client] 退出登录：仍有隧道退出回调未落地，继续清理凭据")
	}

	a.authMu.Lock()
	defer a.authMu.Unlock()
	a.mu.Lock()
	a.authGeneration++
	a.cfg.APIKey = ""
	a.cfg.ServerURL = ""
	a.resetPerAccountState()
	a.mu.Unlock()

	cleared := a.ClearLogs()

	log.Printf("[client] 退出登录：日志缓冲已清空（代次 %d）", cleared.Epoch)
	a.emitState()

	cfgErr := clearMain()
	frpcErr := clearTunnels()

	if cfgErr != nil || frpcErr != nil {
		a.emitState()
		switch {
		case cfgErr != nil && frpcErr != nil:
			return a.GetState(), fmt.Errorf("已退出，但本地凭据清理失败：主配置 %v；隧道配置 %v", cfgErr, frpcErr)
		case cfgErr != nil:
			return a.GetState(), fmt.Errorf("已退出，但本地主配置删除失败: %w", cfgErr)
		default:
			return a.GetState(), fmt.Errorf("已退出，但隧道配置文件删除失败（其中含接入密钥）: %w", frpcErr)
		}
	}
	return a.GetState(), nil
}

func (a *App) resetPerAccountState() {
	a.username = ""
	a.apiKeyMask = ""
	a.tunnels = nil
	a.gatewayHost = ""
	a.gatewayPort = 0
	a.frontendURL = ""
	a.tunnelDomain = ""
	a.trafficUsed = 0
	a.trafficQuota = 0
	a.exceeded = false
	a.group = nil
	a.paymentEnabled = false
	a.balanceCents = 0

	a.applied = map[uint]string{}
	a.cfgRev = map[uint]string{}
	a.tunnelErrs = map[uint]tunnelErr{}
	a.retries = map[uint]*retryState{}
	a.registered = map[uint]bool{}
	a.registeredAt = map[uint]time.Time{}
	a.connectAt = map[uint]time.Time{}
	a.errEmitAt = map[uint]time.Time{}
	a.cleanupWarned = map[uint]bool{}
	a.stopIntents = map[uint]uint64{}
	a.cleanupErr = ""
	a.syncErr = ""
	a.lastSyncAt = time.Time{}
	a.startGen = map[uint]uint64{}
	a.cfgErr = ""
}

func (a *App) currentCredential() (base, apiKey string, err error) {
	base = a.serverBase()
	a.mu.RLock()
	apiKey = a.cfg.APIKey
	a.mu.RUnlock()
	if base == "" || apiKey == "" {
		return "", "", errors.New(a.baseReason())
	}
	return base, apiKey, nil
}

func (a *App) ServerMailEnabled(serverURL string) (bool, error) {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return false, err
	}
	var out struct {
		MailEnabled bool `json:"mail_enabled"`
	}
	if err := a.getJSON(a.rootContext(), base+"/api/public/settings", "", &out); err != nil {
		return false, err
	}
	return out.MailEnabled, nil
}

func (a *App) SendEmailCode(serverURL, email, scene string) error {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{"email": email, "scene": scene})
	if err != nil {
		return err
	}
	_, err = a.do(a.rootContext(), http.MethodPost, base+"/api/user/auth/send-email-code", "", payload)
	return err
}

func (a *App) ResetPassword(serverURL, account, oldPassword, emailCode, newPassword string) error {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{
		"account":      account,
		"old_password": oldPassword,
		"email_code":   emailCode,
		"password":     newPassword,
	})
	if err != nil {
		return err
	}
	_, err = a.do(a.rootContext(), http.MethodPost, base+"/api/user/auth/reset-password", "", payload)
	return err
}
