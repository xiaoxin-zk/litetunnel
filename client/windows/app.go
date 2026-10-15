package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/xiaoxin-zk/litetunnel/client/internal/localsvc"
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

	// LastSyncAt 是最近一次成功同步的时间，界面上用于显示「刚刚同步」。
	LastSyncAt *time.Time `json:"last_sync_at"`
	// SyncErr 非空表示最近一次自动同步失败（通常是网络问题）。
	SyncErr string `json:"sync_err"`
	// Version 是客户端构建版本。
	//
	// 客户端出问题时第一个要确认的永远是「你跑的是哪个版本」——
	// 没有它就只能靠对比 exe 体积去猜，既不可靠也让排查绕远路。
	Version string `json:"version"`
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

	// appliedConfig 是最近一次写入磁盘的 frpc 配置原文。
	//
	// 自动同步靠比较它来判断「服务端配置有没有变」：只有真的变了才重启 frpc。
	// 不比较的话每 20 秒重启一次，隧道会处于持续的断连抖动中。
	appliedConfig string
	lastSyncAt    time.Time
	syncErr       string

	// syncMu 串行化同步操作。后台定时同步与用户手动点「立即同步」
	// 可能同时发生，两者都会写 frpc.toml 并可能重启 frpc，
	// 重叠执行会造成无谓的重复重启（表现为连接反复闪断）。
	syncMu sync.Mutex
}

// syncInterval 是后台自动同步的间隔。
//
// 取 20 秒是折中：用户在网页端加完隧道再切回客户端，基本已经同步好了；
// 而每次同步只是两个轻量 GET，不会给服务端造成压力。
const syncInterval = 20 * time.Second

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

	// 优先使用内嵌的 frpc：正式发布包里只有这一个 exe。
	// 取不到（开发构建或释放失败）时传空串，
	// 由 Manager 回退到「在程序目录与 PATH 中查找」。
	exePath, err := ensureFrpc()
	if err != nil {
		log.Printf("[client] %v，将回退到同目录查找 frpc.exe", err)
		exePath = ""
	}

	return &App{
		cfg: cfg,
		mgr: frpc.New(exePath),
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

	// 自动同步常驻运行：即使没连 frpc 也要同步，
	// 因为用户在网页端改了隧道后，客户端列表应当自己跟上。
	a.startAutoSync(ctx)

	if a.cfg.AutoStart && a.cfg.APIKey != "" {
		go func() {
			time.Sleep(800 * time.Millisecond)
			_ = a.StartClient()
		}()
	}
}

// shutdown 在客户端退出前被调用，确保 frpc 子进程一并结束。
//
// 这是「正常关闭」这条路径的清理。异常退出（崩溃、被任务管理器强杀、
// 系统关机时的强制终止）走不到这里，由 frpc 包里的 Job Object 兜底——
// 两者是互补关系，缺任何一层都会留下孤儿进程。
func (a *App) shutdown(ctx context.Context) {
	if err := a.mgr.Stop(); err != nil {
		log.Printf("[client] 退出时停止 frpc 失败: %v", err)
	}
}

// ---- 状态 ----

// GetState 返回当前完整状态。
func (a *App) GetState() State {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// 零值时间序列化成 "0001-01-01T00:00:00Z"，前端没法用它判断
	// 「还没同步过」，所以未同步时下发 null。
	var lastSync *time.Time
	if !a.lastSyncAt.IsZero() {
		t := a.lastSyncAt
		lastSync = &t
	}

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
		SyncErr:        a.syncErr,
		LastSyncAt:     lastSync,
		Version:        Version(),
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
	cfgText = strings.TrimSpace(cfgText)
	if cfgText == "" {
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
	// 记录「已写入磁盘的配置」。
	//
	// 必须在这里记，否则自动同步的第一个 tick 会把刚写好的配置
	// 误判成「服务端有更新」，触发一次完全没必要的 frpc 重启——
	// 用户看到的就是「刚连上就闪断一次」。
	a.appliedConfig = cfgText
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

// ListLocalServices 枚举本机正在监听的服务，供用户在建隧道时点选。
//
// 刻意不要求已登录：用户完全可能在连接之前就想看看自己有哪些服务，
// 而这个动作既不访问网络、也不涉及账号数据。
func (a *App) ListLocalServices() ([]localsvc.Service, error) {
	return localsvc.List()
}

// CreateTunnel 创建一条隧道。
//
// remotePort 传 0 表示由服务端自动分配：客户端刻意不暴露「远程端口」
// 这个概念，用户只需要知道「本机服务跑在哪个端口」。
// 端口池的挑选、系统占用排除、保留端口过滤全在服务端完成。
func (a *App) CreateTunnel(name, tunnelType, localIP string, localPort, remotePort int, subdomain string) (State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}

	// subdomain 只对 HTTP/HTTPS 有意义：那两类隧道没有公网端口，
	// 靠域名区分。服务端在两者都为空时会直接拒绝，所以必须带上。
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
	if _, err := a.do(http.MethodPost, base+"/api/user/tunnels", apiKey, payload); err != nil {
		return a.GetState(), err
	}
	// 建完立刻同步：新建的隧道会带上下发的公网地址，
	// 让用户马上看到「该发给朋友哪个地址」。
	return a.Refresh()
}

// BatchFailure 记录批量创建中一条失败。
type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

// BatchResult 是批量创建的结果。
//
// 不绑定 created 字段：建完就调 Refresh 重新拉列表，
// 那条路径已经保证了列表与配置都是最新的，再解析一遍是多余的。
type BatchResult struct {
	Message  string         `json:"message"`
	Failures []BatchFailure `json:"failures"`
}

// CreateTunnelsBatch 批量创建隧道。
//
// 服务端逐条创建、不整体回滚：用户要的是一批端口尽可能都建好，
// 而不是「一条失败就全都没了」。失败原因逐条带回，用户才知道
// 该去改哪一个。
func (a *App) CreateTunnelsBatch(namePrefix, tunnelType, localIP string, ports []int) (BatchResult, State, error) {
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

	raw, err := a.do(http.MethodPost, base+"/api/user/tunnels/batch", apiKey, payload)
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	var out BatchResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return BatchResult{}, a.GetState(), err
	}

	// 建完立刻同步：新建的隧道会带上下发的公网地址。
	// 同步失败时不把整体判为失败——隧道其实已经建好了。
	state, rerr := a.Refresh()
	if rerr != nil {
		return out, a.GetState(), nil
	}
	return out, state, nil
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

// ---- 自动同步 ----

// startAutoSync 启动后台自动同步，随应用退出而结束。
//
// 为什么必须有它：用户完全可能在网页控制台里加一条隧道，
// 而客户端此刻正在运行。没有自动同步的话，他必须手动点「同步配置」，
// 更糟的是——即使点了，运行中的 frpc 也不会加载新配置，
// 于是「隧道明明建好了却连不上」，用户只会认为产品坏了。
func (a *App) startAutoSync(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(syncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.autoSyncOnce()
			}
		}
	}()
}

// autoSyncOnce 执行一次后台同步。
//
// 失败只记录不弹窗：网络抖动是常态，每 20 秒弹一次错误会把人逼疯。
// 错误信息通过 State.SyncErr 呈现为一个低调的提示。
func (a *App) autoSyncOnce() {
	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()
	if apiKey == "" {
		// 尚未接入，没有可同步的东西。
		return
	}

	changed, err := a.syncLocked()
	if err != nil {
		a.setSyncErr(err)
		// 重启失败意味着 frpc 已经被停掉且没能起来——这必须显式提示。
		// 只放在状态区的小字里，用户根本不会注意到，
		// 只会发现「隧道莫名其妙全掉线了」。
		if changed {
			a.emitNotice("配置已更新，但重启 frpc 失败：" + err.Error())
		}
		a.emitState()
		return
	}

	if changed && a.mgr.Running() {
		// 明确告知用户「列表变了、已自动重连」，否则他会疑惑
		// 为什么隧道列表自己动了、连接为什么闪了一下。
		a.emitNotice("检测到配置变更，已自动同步并重新连接")
	}
	a.emitState()
}

// syncLocked 在一次互斥的保护下完成「拉取 → 判断变化 → 必要时重启 frpc」。
//
// 抽出这个方法而不是让两处各自组合：手动同步和自动同步一旦逻辑分叉，
// 迟早会出现「按钮点的能用、后台同步的不能用」这类难以复现的问题。
func (a *App) syncLocked() (cfgChanged bool, err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	cfgChanged, err = a.applySync()
	if err != nil {
		return false, err
	}
	if cfgChanged {
		if err := a.reloadRunning(); err != nil {
			return true, err
		}
	}
	return cfgChanged, nil
}

// applySync 从服务端拉取隧道清单与 frpc 配置。
//
// 返回 cfgChanged 表示服务端生成的配置与本地已写入的不同。
// 这个返回值是「是否需要重启 frpc」的唯一依据——不比较就重启的话，
// 隧道会每 20 秒抖动一次。
func (a *App) applySync() (cfgChanged bool, err error) {
	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	prevCfg := a.appliedConfig
	a.mu.RUnlock()

	if base == "" || apiKey == "" {
		return false, errors.New("尚未接入")
	}

	var data clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", apiKey, &data); err != nil {
		return false, err
	}

	// 配置拉取失败不拖垮整次同步：清单已经拿到了，
	// 只是这次不判断配置变化（cfgText 保持空 → cfgChanged 为 false）。
	var cfgText string
	if err := a.getRaw(base+"/api/user/client/config", apiKey, &cfgText); err != nil {
		cfgText = ""
	}
	cfgText = strings.TrimSpace(cfgText)

	// 服务端没返回配置（例如一条隧道都没有）时不覆盖本地文件，
	// 否则会把一份可用的配置清空。
	cfgChanged = cfgText != "" && cfgText != prevCfg
	if cfgChanged {
		if err := writeFrpcConfig(cfgText); err != nil {
			return false, err
		}
		// 把「哪一行变了」写进日志。
		//
		// 自动同步在配置变化时会重启 frpc，表现为「隧道莫名断一下」。
		// 没有这条信息的话，用户只知道「又重启了」，而我们从日志里
		// 完全看不出是哪一行变了——只能靠猜。有了它一眼就能定位。
		a.emitLog("服务端配置有变化，已更新本地 frpc.toml（" + diffHint(prevCfg, cfgText) + "）")
	}

	a.mu.Lock()
	if cfgChanged {
		a.appliedConfig = cfgText
	}
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
	a.lastSyncAt = time.Now()
	a.syncErr = ""
	a.mu.Unlock()

	return cfgChanged, nil
}

// reloadRunning 在 frpc 运行中时重启它，让新配置生效。
//
// 用「停 + 起」而不是 frpc 的 reload 接口：后者需要在 frpc.toml 里
// 额外开一个本地管理端口，多一个暴露面；而重启的代价只是约一秒的连接中断。
func (a *App) reloadRunning() error {
	if !a.mgr.Running() {
		return nil
	}
	path, err := frpcConfigPath()
	if err != nil {
		return err
	}
	_ = a.mgr.Stop()
	if err := a.mgr.Start(path); err != nil {
		return fmt.Errorf("配置已更新，但重启 frpc 失败: %w", err)
	}
	return nil
}

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

// emitLog 往客户端的运行日志里追加一行。
//
// 与 frpc 自己的输出走同一个通道，这样用户在界面上看到的顺序
// 就是真实发生的顺序——排查时序问题时这一点很重要。
func (a *App) emitLog(line string) {
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "log", "[系统] "+line)
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

func shortLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
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

// ---- 客户端进程 ----

// StartClient 写入最新配置并启动 frpc。
func (a *App) StartClient() error {
	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if apiKey == "" {
		return errors.New("请先使用 API Key 接入")
	}

	// 启动前先同步一次，避免使用过期配置。
	//
	// 这里必须走 syncLocked 而不是自己拼一遍请求：syncLocked 会记录
	// appliedConfig，而手工拉取不会——那样下一个自动同步的 tick 就会
	// 误判「配置变了」并触发一次完全没必要的重启。
	// 更糟的是那次重启会把刚起来的 frpc 停掉，用户看到的就是
	// 「连上十几秒后自动断开」。
	//
	// frpc 此刻尚未运行，因此 syncLocked 内部的 reloadRunning 会直接返回，
	// 不会出现「先重启再启动」的怪事。
	if _, err := a.syncLocked(); err != nil {
		// 同步失败不阻塞启动：本地已有的 frpc.toml 可能仍然可用，
		// 直接启动比什么都不做要好。错误记下来供状态区展示。
		a.setSyncErr(err)
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
