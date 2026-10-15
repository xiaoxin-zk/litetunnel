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
	// ServerURL 是本次实际使用的服务端地址（构建注入的优先）。
	ServerURL string `json:"server_url"`
	// ServerFixed 为 true 表示地址由构建注入，界面不提供修改入口。
	ServerFixed bool `json:"server_fixed"`
	// NeedsServerURL 为 true 表示构建未注入地址，需要手填（仅本地调试构建）。
	NeedsServerURL bool `json:"needs_server_url"`

	LoggedIn bool `json:"logged_in"`
	// Username 由服务端下发：客户端只持有 API Key，不填账号。
	Username string `json:"username"`
	// APIKeyMask 是脱敏后的 Key，仅用于界面展示。
	APIKeyMask string `json:"api_key_mask"`

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

	// Group 是分组限制，客户端据此限制建隧道表单的可选项
	// （允许哪些协议、最多几条），避免放行注定被拒的提交。
	Group *groupLimit `json:"group,omitempty"`
	// PaymentEnabled 为 false 时客户端不展示任何余额相关内容：
	// 没有充值入口时，一个恒为 0 的余额只会造成困惑。
	PaymentEnabled bool  `json:"payment_enabled"`
	BalanceCents   int64 `json:"balance_cents"`
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
	username     string
	apiKeyMask   string
	gatewayHost  string
	gatewayPort  int
	tunnelDomain string
	trafficUsed  int64
	trafficQuota int64
	exceeded     bool
	lastError    string

	group          *groupLimit
	paymentEnabled bool
	balanceCents   int64
}

// maskKey 生成用于界面展示的脱敏形式，避免完整 Key 长时间暴露在屏幕上。
func maskKey(k string) string {
	if len(k) <= 12 {
		return "****"
	}
	return k[:12] + "********"
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

	if a.cfg.AutoStart && a.cfg.APIKey != "" {
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
		ServerURL:      a.cfg.ServerURL,
		ServerFixed:    serverFixed(),
		NeedsServerURL: !serverFixed() && a.cfg.ServerURL == "",
		LoggedIn:       a.cfg.APIKey != "",
		Username:       a.username,
		APIKeyMask:     a.apiKeyMask,
		GatewayHost:    a.gatewayHost,
		GatewayPort:    a.gatewayPort,
		TunnelDomain:   a.tunnelDomain,
		Tunnels:        a.tunnels,
		TrafficUsed:    a.trafficUsed,
		TrafficQuota:   a.trafficQuota,
		Exceeded:       a.exceeded,
		Group:          a.group,
		PaymentEnabled: a.paymentEnabled,
		BalanceCents:   a.balanceCents,
		Running:        a.mgr.Running(),
		FrpcFound:      a.mgr.Available(),
		FrpcPath:       a.mgr.ExePath(),
		AutoStart:      a.cfg.AutoStart,
	}
	// 构建注入了地址时，界面上始终展示它，而不是本地残留的旧值。
	if fixed := defaultServerURL(); fixed != "" {
		state.ServerURL = fixed
	}
	if p, err := frpcConfigPath(); err == nil {
		state.ConfigPath = p
	}
	if state.Tunnels == nil {
		state.Tunnels = []TunnelVO{}
	}
	return state
}

// ---- 接入与配置同步 ----

type clientInfo struct {
	ServerAddr   string `json:"server_addr"`
	ServerPort   int    `json:"server_port"`
	User         string `json:"user"`
	TunnelDomain string `json:"tunnel_domain"`
}

// groupLimit 是分组对建隧道的约束，客户端据此限制表单可选项。
type groupLimit struct {
	Name              string `json:"name"`
	MaxTunnels        int    `json:"max_tunnels"`
	AllowProtocols    string `json:"allow_protocols"`
	AllowCustomDomain bool   `json:"allow_custom_domain"`
	BandwidthLimitStr string `json:"bandwidth_limit_str"`
}

type clientInfoData struct {
	clientInfo
	Username     string      `json:"username"`
	Nickname     string      `json:"nickname"`
	Tunnels      []TunnelVO  `json:"tunnels"`
	TrafficUsed  int64       `json:"traffic_used"`
	TrafficQuota int64       `json:"traffic_quota"`
	Exceeded     bool        `json:"exceeded"`
	Group        *groupLimit `json:"group,omitempty"`
	// BalanceCents 与 PaymentEnabled 一起使用：
	// 站点未启用支付时客户端不展示任何余额相关内容。
	BalanceCents   int64 `json:"balance_cents"`
	PaymentEnabled bool  `json:"payment_enabled"`
}

// serverBase 返回本次运行使用的服务端地址：构建注入的优先。
func (a *App) serverBase() string {
	if base := defaultServerURL(); base != "" {
		return base
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return strings.TrimRight(a.cfg.ServerURL, "/")
}

// Connect 使用 API Key 接入平台。
//
// 用户只需要粘贴一个 Key，其余全部自动完成：
//   - 服务端地址：构建时注入，不需要填；
//   - 账号信息：由服务端下发，不需要填；
//   - frpc 接入凭据：服务端生成在配置文件里，不需要填。
//
// serverURL 仅在构建未注入地址时使用（本地调试构建）。
func (a *App) Connect(apiKey, serverURL string) (State, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return a.GetState(), errors.New("请填写 API Key")
	}

	base, err := a.resolveBase(serverURL)
	if err != nil {
		return a.GetState(), err
	}

	// 先用 info 接口验证 Key 是否有效，同时拿到账号信息。
	var info clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", apiKey, &info); err != nil {
		return a.GetState(), err
	}

	// 再拉取服务端生成的 frpc.toml（内含每用户独立的接入凭据）。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", apiKey, &cfgText); err != nil {
		return a.GetState(), err
	}
	if strings.TrimSpace(cfgText) == "" {
		return a.GetState(), errors.New("服务端未返回客户端配置，请先在控制台创建隧道")
	}
	if err := writeFrpcConfig(cfgText); err != nil {
		return a.GetState(), err
	}

	username := info.Username
	if username == "" {
		username = info.Nickname
	}

	a.mu.Lock()
	a.cfg.APIKey = apiKey
	a.cfg.ServerURL = base
	a.username = username
	a.apiKeyMask = maskKey(apiKey)
	a.gatewayHost = info.ServerAddr
	a.gatewayPort = info.ServerPort
	a.tunnelDomain = info.TunnelDomain
	a.tunnels = info.Tunnels
	a.trafficUsed = info.TrafficUsed
	a.trafficQuota = info.TrafficQuota
	a.exceeded = info.Exceeded
	a.group = info.Group
	a.paymentEnabled = info.PaymentEnabled
	a.balanceCents = info.BalanceCents
	a.lastError = ""
	if a.tunnels == nil {
		a.tunnels = []TunnelVO{}
	}
	a.mu.Unlock()

	if err := saveConfig(a.cfg); err != nil {
		return a.GetState(), err
	}
	return a.GetState(), nil
}

// Logout 清除本地凭据并停止客户端。
func (a *App) Logout() State {
	_ = a.mgr.Stop()

	a.mu.Lock()
	a.cfg.APIKey = ""
	a.cfg.ServerURL = ""
	a.username = ""
	a.apiKeyMask = ""
	a.tunnels = nil
	a.gatewayHost = ""
	a.gatewayPort = 0
	a.tunnelDomain = ""
	a.trafficUsed = 0
	a.trafficQuota = 0
	a.exceeded = false
	a.group = nil
	a.paymentEnabled = false
	a.balanceCents = 0
	a.mu.Unlock()

	_ = clearConfig()
	return a.GetState()
}

// currentCredential 返回当前接入用的长期凭据。
//
// 抽成一个方法而不是各处直接读 a.cfg.APIKey，是为了让加锁这件事
// 只发生在一个地方——这类字段被多处并发读写时最容易漏锁。
func (a *App) currentCredential() (base, apiKey string, err error) {
	base = a.serverBase()
	a.mu.RLock()
	apiKey = a.cfg.APIKey
	a.mu.RUnlock()
	if base == "" || apiKey == "" {
		return "", "", errors.New("尚未接入，请先连接")
	}
	return base, apiKey, nil
}

// CreateTunnel 创建一条隧道。
//
// remotePort 传 0 表示由服务端自动分配：客户端刻意不暴露「远程端口」
// 这个概念，用户只需要知道「本机服务跑在哪个端口」。
// 端口池的挑选、系统占用排除、保留端口过滤全在服务端完成。
func (a *App) CreateTunnel(name, tunnelType, localIP string, localPort, remotePort int) (State, error) {
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
	})
	if err != nil {
		return a.GetState(), err
	}
	if _, err := a.do(http.MethodPost, base+"/api/user/tunnels", apiKey, payload); err != nil {
		return a.GetState(), err
	}
	// 建完立刻同步：新建的隧道会带上下发的公网地址，
	// 让用户马上看到「该发给朋友哪个地址」。
	return a.Refresh()
}

// DeleteTunnel 删除一条隧道。
func (a *App) DeleteTunnel(id uint) (State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d", base, id)
	if _, err := a.do(http.MethodDelete, endpoint, apiKey, nil); err != nil {
		return a.GetState(), err
	}
	return a.Refresh()
}

// SetTunnelStatus 启用或停用一条隧道。
func (a *App) SetTunnelStatus(id uint, status string) (State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	payload, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return a.GetState(), err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d/status", base, id)
	if _, err := a.do(http.MethodPost, endpoint, apiKey, payload); err != nil {
		return a.GetState(), err
	}
	return a.Refresh()
}

// Redeem 使用兑换码。
//
// 返回服务端给出的结果文案（例如「流量额度已增加 10 GB」），
// 由调用方直接提示用户——不同兑换码类型的文案差别很大，
// 在客户端里猜类型容易说错。
func (a *App) Redeem(code string) (string, State, error) {
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
	raw, err := a.do(http.MethodPost, base+"/api/user/redeem", apiKey, payload)
	if err != nil {
		return "", a.GetState(), err
	}

	var out struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &out)

	// 兑换可能改变配额或分组，同步一次让界面立刻反映最新状态。
	state, rerr := a.Refresh()
	if rerr != nil {
		return out.Message, a.GetState(), nil
	}
	return out.Message, state, nil
}

// Refresh 从服务端同步隧道清单与最新配置。
func (a *App) Refresh() (State, error) {
	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if base == "" || apiKey == "" {
		return a.GetState(), errors.New("尚未接入")
	}

	var data clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", apiKey, &data); err != nil {
		return a.GetState(), err
	}

	// 同时刷新 frpc.toml，保证新增/删除隧道后本地配置同步。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", apiKey, &cfgText); err == nil && cfgText != "" {
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
	a.group = data.Group
	a.paymentEnabled = data.PaymentEnabled
	a.balanceCents = data.BalanceCents
	if data.Username != "" {
		a.username = data.Username
	}
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
	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if apiKey == "" {
		return errors.New("请先使用 API Key 接入")
	}

	// 启动前先同步一次配置，避免使用过期隧道列表。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", apiKey, &cfgText); err == nil && cfgText != "" {
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

// resolveBase 统一解析服务端地址。
//
// 构建注入的地址优先：正式客户端只认内置地址，用户无从篡改，
// 也就不会被诱导连到钓鱼服务器。未注入时才用界面上填写的（仅调试构建）。
func (a *App) resolveBase(serverURL string) (string, error) {
	if base := defaultServerURL(); base != "" {
		return base, nil
	}
	return normalizeServerURL(serverURL)
}

// ServerMailEnabled 查询服务端是否启用了邮件功能。
//
// 客户端据此决定重置密码走哪条路：启用邮件就用邮箱验证码，
// 未启用就用「当前密码 + 新密码」。这一步必须先问服务端，
// 而不是在客户端写死——否则服务端配置一变，客户端就失效了。
func (a *App) ServerMailEnabled(serverURL string) (bool, error) {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return false, err
	}
	var out struct {
		MailEnabled bool `json:"mail_enabled"`
	}
	if err := a.getJSON(base+"/api/public/settings", "", &out); err != nil {
		return false, err
	}
	return out.MailEnabled, nil
}

// SendEmailCode 请求服务端发送邮箱一次性验证码。scene 为 register 或 reset。
func (a *App) SendEmailCode(serverURL, email, scene string) error {
	base, err := a.resolveBase(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]string{"email": email, "scene": scene})
	if err != nil {
		return err
	}
	_, err = a.do(http.MethodPost, base+"/api/user/auth/send-email-code", "", payload)
	return err
}

// ResetPassword 重置账号密码。
//
// 两种材料一起提交，由服务端按自身配置选择校验方式：
//   - 启用邮件 → 校验 email_code
//   - 未启用邮件 → 校验 old_password
//
// 客户端不自己判断走哪条路，是为了避免两边规则不一致导致
// 「客户端以为该用验证码、服务端却在等旧密码」这类错配。
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
	_, err = a.do(http.MethodPost, base+"/api/user/auth/reset-password", "", payload)
	return err
}

func (a *App) getJSON(endpoint, token string, out any) error {
	body, err := a.do(http.MethodGet, endpoint, token, nil)
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
