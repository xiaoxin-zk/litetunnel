package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

// TunnelVO 隧道视图对象。
type TunnelVO struct {
	ID                uint   `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	LocalIP           string `json:"local_ip"`
	LocalPort         int    `json:"local_port"`
	PublicAddr        string `json:"public_addr"`
	Status            string `json:"status"`
	Online            bool   `json:"online"`
	TrafficUsed       int64  `json:"traffic_used"`
	BandwidthLimitStr string `json:"bandwidth_limit_str"`
}

// State 是前端渲染所需的完整状态。
type State struct {
	ServerURL    string     `json:"server_url"`
	LoggedIn     bool       `json:"logged_in"`
	Username     string     `json:"username"`
	GatewayHost  string     `json:"gateway_host"`
	GatewayPort  int        `json:"gateway_port"`
	TunnelDomain string     `json:"tunnel_domain"`
	Tunnels      []TunnelVO `json:"tunnels"`
	TrafficUsed  int64      `json:"traffic_used"`
	TrafficQuota int64      `json:"traffic_quota"`
	Exceeded     bool       `json:"exceeded"`

	Running    bool   `json:"running"`
	FrpcFound  bool   `json:"frpc_found"`
	FrpcPath   string `json:"frpc_path"`
	ConfigPath string `json:"config_path"`
	AutoStart  bool   `json:"auto_start"`
}

// App 是暴露给前端的应用对象。
type App struct {
	ctx context.Context

	mu   sync.RWMutex
	cfg  *Config
	mgr  *frpc.Manager
	http *http.Client

	// 服务端返回的运行态缓存
	tunnels      []TunnelVO
	gatewayHost  string
	gatewayPort  int
	tunnelDomain string
	trafficUsed  int64
	trafficQuota int64
	exceeded     bool
	lastError    string
}

// NewApp 构造应用对象。
func NewApp() *App {
	cfg, _ := loadConfig()
	return &App{
		cfg: cfg,
		mgr: frpc.New(""),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// startup 由 Wails 在窗口就绪后调用。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.mgr.SetCallbacks(func(line string) {
		wailsruntime.EventsEmit(a.ctx, "log", line)
	}, func(err error) {
		state := a.GetState()
		wailsruntime.EventsEmit(a.ctx, "state", state)
		_ = err
	})

	if a.cfg.AutoStart && a.cfg.Token != "" {
		go func() {
			time.Sleep(800 * time.Millisecond)
			_ = a.StartClient()
		}()
	}
}

// ---- 状态 ----

// GetState 返回当前完整状态。
func (a *App) GetState() State {
	a.mu.RLock()
	defer a.mu.RUnlock()

	state := State{
		ServerURL:    a.cfg.ServerURL,
		LoggedIn:     a.cfg.Token != "",
		Username:     a.cfg.Username,
		GatewayHost:  a.gatewayHost,
		GatewayPort:  a.gatewayPort,
		TunnelDomain: a.tunnelDomain,
		Tunnels:      a.tunnels,
		TrafficUsed:  a.trafficUsed,
		TrafficQuota: a.trafficQuota,
		Exceeded:     a.exceeded,
		Running:      a.mgr.Running(),
		FrpcFound:    a.mgr.Available(),
		FrpcPath:     a.mgr.ExePath(),
		AutoStart:    a.cfg.AutoStart,
	}
	if p, err := frpcConfigPath(); err == nil {
		state.ConfigPath = p
	}
	if state.Tunnels == nil {
		state.Tunnels = []TunnelVO{}
	}
	return state
}

// ---- 登录与配置同步 ----

type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type clientInfo struct {
	ServerAddr   string `json:"server_addr"`
	ServerPort   int    `json:"server_port"`
	User         string `json:"user"`
	Token        string `json:"token"`
	TunnelDomain string `json:"tunnel_domain"`
}

type clientAuthData struct {
	Client clientInfo `json:"client"`
	Config string     `json:"config"`
}

type clientInfoData struct {
	clientInfo
	Tunnels      []TunnelVO `json:"tunnels"`
	TrafficUsed  int64      `json:"traffic_used"`
	TrafficQuota int64      `json:"traffic_quota"`
	Exceeded     bool       `json:"exceeded"`
}

// Login 使用账号密码换取客户端接入凭据，并保存下发的 frpc 配置。
func (a *App) Login(serverURL, username, password string) (State, error) {
	base, err := normalizeServerURL(serverURL)
	if err != nil {
		return a.GetState(), err
	}

	var data clientAuthData
	err = a.postJSON(base+"/api/user/client/auth", "", loginPayload{Username: username, Password: password}, &data)
	if err != nil {
		return a.GetState(), err
	}

	if err := writeFrpcConfig(data.Config); err != nil {
		return a.GetState(), err
	}

	a.mu.Lock()
	a.cfg.ServerURL = base
	a.cfg.Token = data.Client.Token
	a.cfg.Username = username
	a.gatewayHost = data.Client.ServerAddr
	a.gatewayPort = data.Client.ServerPort
	a.tunnelDomain = data.Client.TunnelDomain
	a.lastError = ""
	a.mu.Unlock()

	if err := saveConfig(a.cfg); err != nil {
		return a.GetState(), err
	}

	// 拉一次隧道清单，登录后立即展示。
	_, _ = a.Refresh()
	return a.GetState(), nil
}

// Logout 清除本地凭据并停止客户端。
func (a *App) Logout() State {
	_ = a.mgr.Stop()

	a.mu.Lock()
	a.cfg.Token = ""
	a.cfg.Username = ""
	a.tunnels = nil
	a.gatewayHost = ""
	a.gatewayPort = 0
	a.tunnelDomain = ""
	a.trafficUsed = 0
	a.trafficQuota = 0
	a.exceeded = false
	a.mu.Unlock()

	_ = clearConfig()
	return a.GetState()
}

// Refresh 从服务端同步隧道清单与最新配置。
func (a *App) Refresh() (State, error) {
	a.mu.RLock()
	base, token := a.cfg.ServerURL, a.cfg.Token
	a.mu.RUnlock()

	if base == "" || token == "" {
		return a.GetState(), errors.New("尚未登录")
	}

	var data clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", token, &data); err != nil {
		return a.GetState(), err
	}

	// 同时刷新 frpc.toml，保证新增/删除隧道后本地配置同步。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", token, &cfgText); err == nil && cfgText != "" {
		_ = writeFrpcConfig(cfgText)
	}

	a.mu.Lock()
	a.tunnels = data.Tunnels
	a.gatewayHost = data.ServerAddr
	a.gatewayPort = data.ServerPort
	a.tunnelDomain = data.TunnelDomain
	a.trafficUsed = data.TrafficUsed
	a.trafficQuota = data.TrafficQuota
	a.exceeded = data.Exceeded
	if a.tunnels == nil {
		a.tunnels = []TunnelVO{}
	}
	a.mu.Unlock()

	state := a.GetState()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "state", state)
	}
	return state, nil
}

// ---- 客户端进程 ----

// StartClient 写入最新配置并启动 frpc。
func (a *App) StartClient() error {
	a.mu.RLock()
	base, token := a.cfg.ServerURL, a.cfg.Token
	a.mu.RUnlock()

	if token == "" {
		return errors.New("请先登录")
	}

	// 启动前先同步一次配置，避免使用过期隧道列表。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", token, &cfgText); err == nil && cfgText != "" {
		if err := writeFrpcConfig(cfgText); err != nil {
			return err
		}
	}

	path, err := frpcConfigPath()
	if err != nil {
		return err
	}
	if err := a.mgr.Start(path); err != nil {
		return err
	}

	state := a.GetState()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "state", state)
	}
	return nil
}

// StopClient 停止 frpc。
func (a *App) StopClient() error {
	if err := a.mgr.Stop(); err != nil {
		return err
	}
	state := a.GetState()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "state", state)
	}
	return nil
}

// GetLogs 返回日志快照。
func (a *App) GetLogs() []string {
	return a.mgr.Logs()
}

// ClearLogs 清空日志缓冲。
func (a *App) ClearLogs() {
	a.mgr.ClearLogs()
}

// SetAutoStart 设置开机自动连接。
func (a *App) SetAutoStart(enabled bool) error {
	a.mu.Lock()
	a.cfg.AutoStart = enabled
	a.mu.Unlock()
	return saveConfig(a.cfg)
}

// OpenDataDir 在资源管理器中打开数据目录。
func (a *App) OpenDataDir() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("explorer", dir).Start()
	case "darwin":
		_ = exec.Command("open", dir).Start()
	default:
		_ = exec.Command("xdg-open", dir).Start()
	}
	return dir, nil
}

// ---- HTTP 辅助 ----

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func normalizeServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("请填写服务器地址")
	}
	if !strings.Contains(raw, "://") {
		// 未写协议时按 https 处理，避免凭据走明文。
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("服务器地址格式不正确")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("仅支持 http 或 https 协议")
	}
	if u.Host == "" {
		return "", errors.New("服务器地址缺少主机名")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

func (a *App) getJSON(endpoint, token string, out any) error {
	body, err := a.do(http.MethodGet, endpoint, token, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (a *App) postJSON(endpoint, token string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body, err := a.do(http.MethodPost, endpoint, token, raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (a *App) getRaw(endpoint, token string, out *string) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接服务器: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回状态码 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	*out = string(data)
	return nil
}

func (a *App) do(method, endpoint, token string, payload []byte) (json.RawMessage, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接服务器，请检查地址与网络: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("服务器响应格式异常（状态码 %d）", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || env.Code != 0 {
		msg := env.Message
		if msg == "" {
			msg = fmt.Sprintf("请求失败（状态码 %d）", resp.StatusCode)
		}
		return nil, errors.New(msg)
	}
	return env.Data, nil
}

func writeFrpcConfig(text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("服务端返回的配置为空")
	}
	path, err := frpcConfigPath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("写入客户端配置失败: %w", err)
	}
	return nil
}
