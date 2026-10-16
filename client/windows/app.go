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

// 隧道状态，与服务端 model.Tunnel 的取值一致。
const (
	tunnelStatusActive   = "active"
	tunnelStatusDisabled = "disabled"
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

	// Running 表示本机是否已为这条隧道拉起 frpc 进程。
	//
	// 与 Online 的区别必须分清：Online 是服务端视角（隧道是否已注册到
	// frps），Running 是本机视角（进程在不在）。界面上的开关看的是
	// Running——用户点的是「我这台机器上要不要连出去」。
	Running bool `json:"running"`

	// LastError 是最近一次从该隧道的 frpc 输出里识别到的错误原文。
	//
	// 为什么需要它：「连接中」这个状态本身不说明任何原因——凭据失效、
	// 服务地址不对、网络不通都会停在它上面，用户只能干等。把 frpc 自己
	// 报的错摆出来，才能立刻区分是配置问题还是网络问题。
	LastError   string     `json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`
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

	// ConfigError 非空表示本地配置文件读取失败（通常是文件损坏）。
	//
	// 必须让用户看到：这种情况下客户端会以「未登录」启动，而用户完全
	// 不知道自己是被重置了，只会以为凭据丢了。
	ConfigError string `json:"config_error"`
	// Version 是客户端构建版本。
	//
	// 客户端出问题时第一个要确认的永远是「你跑的是哪个版本」——
	// 没有它就只能靠对比 exe 体积去猜，既不可靠也让排查绕远路。
	Version string `json:"version"`
}

// App 是暴露给前端的应用对象。
type App struct {
	ctx context.Context

	// startedAt 是进程内记录下来的启动时刻。
	//
	// 用途只有一个：把「打开客户端很慢」拆成两段——我们这段（拉清单、
	// 取配置、起进程）和框架这段（窗口与 WebView 初始化，直到前端能收
	// 事件）。不拆开的话，用户说「慢」，日志里只有我们这段的数字，
	// 看不出慢在谁身上。
	startedAt time.Time

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

	// applied 记录每条隧道最近一次写入磁盘的配置原文。
	//
	// 自动同步靠比较它判断「这条隧道的配置有没有变」：只有真的变了才重启
	// 对应的进程。不比较的话每 20 秒重启一次，隧道会处于持续的断连抖动中。
	//
	// 必须按隧道分开存：整份配置属于「全部隧道」，任何一条隧道变更都会
	// 让整份文本不同，于是所有隧道一起重启——那正是要摆脱的行为。
	applied map[uint]string
	lastSyncAt    time.Time
	syncErr       string

	// syncMu 串行化同步操作。后台定时同步与用户的开关操作可能同时发生，
	// 两者都会写配置文件、起停进程；重叠执行会让同一时刻出现
	// 「刚停掉又被拉起来」的反复闪断。
	syncMu sync.Mutex

	// domReadyOnce 保证「打开即连」只跑一次。
	//
	// Wails 的 OnDomReady 挂在 navigationCompleted 上，页面重载（开发时的
	// HMR、或任何一次导航）都会再触发一遍。不挡的话会起出第二个自动同步
	// 协程，表现为「同步频率翻倍」这种很难解释的现象。
	domReadyOnce sync.Once

	// tunnelErrs 记录每条隧道最近一次从 frpc 输出里识别到的错误。
	//
	// 不落盘：它描述的是「这一次运行」的情况，重启后重连一次就有结果了。
	tunnelErrs map[uint]tunnelErr

	// retries 记录每条隧道连续失败次数与下次允许拉起的时间。
	//
	// 没有它的话：frpc 因凭据失效、地址写错等原因立刻退出，下一轮同步
	// （20 秒后）发现进程不在就再拉一次——如此循环，日志每 20 秒重复一遍
	// 同样的错误，而问题一点没变，用户还以为客户端在「努力重连」。
	retries map[uint]*retryState

	// cfgErr 记录本地配置读取失败的原因，通过 State 呈现给用户。
	cfgErr string
}

// retryState 是一条隧道的重试退避状态。
type retryState struct {
	attempts int
	nextAt   time.Time
}

// tunnelErr 是一次 frpc 错误记录。
type tunnelErr struct {
	msg string
	at  time.Time
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
	// 配置读取失败不能吞掉：那通常意味着文件损坏被重置，用户下次打开
	// 会发现自己被登出了，而没有任何线索说明为什么。
	cfg, cfgErr := loadConfig()
	if cfgErr != nil {
		log.Printf("[client] %v", cfgErr)
	}

	// 优先使用内嵌的 frpc：正式发布包里只有这一个 exe。
	// 取不到（开发构建或释放失败）时传空串，
	// 由 Manager 回退到「在程序目录与 PATH 中查找」。
	exePath, err := ensureFrpc()
	if err != nil {
		log.Printf("[client] %v，将回退到同目录查找 frpc.exe", err)
		exePath = ""
	}

	app := &App{
		cfg:        cfg,
		mgr:        frpc.New(exePath),
		applied:    map[uint]string{},
		tunnelErrs: map[uint]tunnelErr{},
		retries:    map[uint]*retryState{},
		startedAt:  time.Now(),
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	if cfgErr != nil {
		app.cfgErr = cfgErr.Error()
	}
	return app
}

// startup 由 Wails 在应用启动时调用（早于窗口加载完成）。
//
// 这里只做准备：注册回调、记下 ctx。真正的「打开即连」放在 domReady，
// 原因见那里。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.mgr.SetCallbacks(func(id uint, name, line string) {
		wailsruntime.EventsEmit(a.ctx, "log", line)
		switch {
		case strings.Contains(line, "start proxy success"):
			// frpc 报告代理启动成功时补一条「现在可以用这个地址了」。
			// 原始输出只有一行 start proxy success，用户看不出这意味着
			// 「可以把地址发给朋友了」——而那恰恰是他最需要的信息。
			a.clearTunnelErr(id)
			// 连上了就把退避清掉：下次断开时应当立即重试，
			// 而不是继承上一次失败的等待时间。
			a.clearRetry(id)
			a.emitTunnelReady(id, name)
		case frpc.IsErrorLine(line):
			// 记下错误原文并刷新状态，让界面能显示「为什么一直连不上」，
			// 而不是永远停在一句「连接中」上。
			a.recordTunnelErr(id, line)
			a.emitState()
		}
	}, func(id uint, name string, err error, requested bool) {
		switch {
		case requested:
			// 我们自己停的（用户关开关、退出登录、配置变更重连）：
			// 不是失败，不该进入退避——否则用户关掉一条隧道，
			// 界面反而开始报「启动失败，30 秒后重试」。
			a.clearRetry(id)
		default:
			// 非请求退出都算失败并进入退避，包括 err == nil 的情况：
			// frpc 自己干净退出同样意味着这条隧道没在跑，不加退避就会
			// 每 20 秒被重新拉起一次。
			reason := "frpc 已退出"
			if err != nil {
				reason = "frpc 异常退出：" + err.Error()
			}
			a.noteStartFailure(id, name, reason)
		}
		a.emitState()
	})
}

// domReady 在 WebView 加载完成、前端脚本就绪后调用，负责「打开即连」。
//
// # 为什么不能挂在 startup 上
//
// 日志与状态是通过 Wails 事件推给前端的，而在 Windows 上这条推送最终落到
// mainWindow.Invoke —— 它是**同步**的，会一直等到 UI 线程空闲才返回。
//
// 窗口和 WebView 还在初始化时（Chromium 起来要好几秒），从后台协程发出
// 第一条日志，就会把整个启动同步卡在那一刻：frpc 明明只要几毫秒就能拉起来
// （实测 cmd.Start 2-5ms），用户却要等好几秒，而且日志上只看到两条时间
// 相差几秒的记录，完全看不出卡在哪。之前这里用的是「启动后等 800ms」，
// 恰好落在窗口初始化窗口期里，所以每台机器都会中招。
func (a *App) domReady(ctx context.Context) {
	a.domReadyOnce.Do(func() { a.startOnce(ctx) })
}

// startOnce 是 domReady 的实际内容，只允许执行一次（见 domReadyOnce）。
func (a *App) startOnce(ctx context.Context) {
	// 自动同步常驻运行：即使一条隧道都没连也要同步，
	// 因为用户在网页端改了隧道后，客户端列表应当自己跟上。
	a.startAutoSync(ctx)

	// 打开客户端就跟上服务端的开关状态：开关打开着的隧道，各自把进程拉起来。
	//
	// 这里没有任何「要不要自动连接」的判断。曾经有一个「启动客户端后自动
	// 连接」勾选框，还有一个全局「启动连接」按钮，两者都是这套模型之前的
	// 遗留物：连接与否完全由每条隧道自己的开关决定（开关状态存在服务端），
	// 客户端只要在跑就应该跟上。留着它们只会制造「开关是开的，但还得再点
	// 一次才连上」这种状态不一致。
	go func() {
		// 再等一小会儿：OnDomReady 只保证页面加载完成，而前端注册事件
		// 监听是在 Vue 挂载之后，早于它发出的事件会被丢掉（日志第一行
		// 凭空消失，看起来像客户端没干活）。
		time.Sleep(300 * time.Millisecond)

		a.mu.RLock()
		hasKey := a.cfg.APIKey != ""
		a.mu.RUnlock()
		if !hasKey {
			// 还没接入过，没有可同步的东西。
			return
		}

		start := time.Now()
		if _, err := a.syncLocked(); err != nil {
			a.emitLog("启动同步失败：" + err.Error())
		} else {
			// 报「几条在跑、几条是关着的、各花了多久」。
			//
			// 这几项缺一不可：
			//   - 运行数让人知道同步完了；
			//   - 停用数解释了「为什么一条都没起来」——曾经只有运行数，
			//     用户看到「0 条隧道运行中」只会以为客户端坏了，
			//     实际只是那条隧道的开关是关的；
			//   - 两个用时把「客户端慢」拆成两段：我们这段（拉清单、取配置、
			//     起进程）和框架这段（窗口与 WebView 初始化，直到前端能收事件）。
			//     混在一起就永远说不清慢在谁身上。
			a.emitLog(fmt.Sprintf("启动同步完成：%d 条隧道运行中（%d 条已停用，用时 %s，自客户端启动 %s）",
				len(a.mgr.RunningIDs()), a.countDisabledTunnels(),
				time.Since(start).Round(time.Millisecond),
				time.Since(a.startedAt).Round(100*time.Millisecond)))
		}
		a.emitState()
	}()
}

// shutdown 在客户端退出前被调用，确保所有 frpc 子进程一并结束。
//
// 这是「正常关闭」这条路径的清理。异常退出（崩溃、被任务管理器强杀、
// 系统关机时的强制终止）走不到这里，由 frpc 包里的 Job Object 兜底——
// 两者是互补关系，缺任何一层都会留下孤儿进程。
func (a *App) shutdown(ctx context.Context) {
	if err := a.mgr.StopAll(); err != nil {
		log.Printf("[client] 退出时停止 frpc 失败: %v", err)
	}
}

// ---- 状态 ----

// GetState 返回当前完整状态。
func (a *App) GetState() State {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// 最后一道保护：这个方法在启动路径与日志回调里都会被调用，
	// 一旦对 nil 配置取字段就是整个界面白屏（用户只看到「双击没反应」）。
	// loadConfig 现在保证非 nil，这里再兜一层，让以后的改动也炸不出来。
	cfg := a.cfg
	if cfg == nil {
		cfg = &Config{}
	}

	// 零值时间序列化成 "0001-01-01T00:00:00Z"，前端没法用它判断
	// 「还没同步过」，所以未同步时下发 null。
	var lastSync *time.Time
	if !a.lastSyncAt.IsZero() {
		t := a.lastSyncAt
		lastSync = &t
	}

	// 复制一份再补运行态：直接改 a.tunnels 会在只读锁下写共享数据，
	// 而 GetState 会被日志回调高频调用。
	tunnels := make([]TunnelVO, len(a.tunnels))
	copy(tunnels, a.tunnels)
	for i := range tunnels {
		tunnels[i].Running = a.mgr.Running(tunnels[i].ID)
		// 连上之后错误记录已被清掉，这里取不到就表示当前没有已知错误。
		if e, ok := a.tunnelErrs[tunnels[i].ID]; ok {
			at := e.at
			tunnels[i].LastError = e.msg
			tunnels[i].LastErrorAt = &at
		}
	}
	if tunnels == nil {
		tunnels = []TunnelVO{}
	}

	state := State{
		ServerURL:      cfg.ServerURL,
		ServerFixed:    serverFixed(),
		NeedsServerURL: !serverFixed() && cfg.ServerURL == "",
		LoggedIn:       cfg.APIKey != "",
		Username:       a.username,
		APIKeyMask:     a.apiKeyMask,
		GatewayHost:    a.gatewayHost,
		GatewayPort:    a.gatewayPort,
		TunnelDomain:   a.tunnelDomain,
		Tunnels:        tunnels,
		TrafficUsed:    a.trafficUsed,
		TrafficQuota:   a.trafficQuota,
		Exceeded:       a.exceeded,
		Group:          a.group,
		PaymentEnabled: a.paymentEnabled,
		BalanceCents:   a.balanceCents,
		SyncErr:        a.syncErr,
		LastSyncAt:     lastSync,
		ConfigError:    a.cfgErr,
		Version:        Version(),
		// Running 是「有没有任意一条隧道在连」，界面的状态点用它。
		Running:   a.mgr.AnyRunning(),
		FrpcFound: a.mgr.Available(),
		FrpcPath:  a.mgr.ExePath(),
	}
	// 构建注入了地址时，界面上始终展示它，而不是本地残留的旧值。
	if fixed := defaultServerURL(); fixed != "" {
		state.ServerURL = fixed
	}
	if p, err := frpcTunnelsDir(); err == nil {
		state.ConfigPath = p
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

	// 先用 info 接口验证 Key 是否有效，同时拿到账号信息与隧道清单。
	var info clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", apiKey, &info); err != nil {
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

	// 接入之后立刻同步一次：所有「已启用」的隧道会各自拉起一个 frpc 进程。
	//
	// 客户端刻意没有「启动连接」这个步骤——用户已经明确表达过「哪些隧道
	// 要开着」（隧道自己的开关状态），再让他点一次全局按钮，只会造成
	// 「开了开关却没连上，还得再点一次」这种状态不一致。
	if _, err := a.syncLocked(); err != nil {
		// 同步失败不阻塞接入：凭据已经保存，界面能显示账号信息，
		// 错误通过 SyncErr 呈现，下一个自动同步周期还会重试。
		a.setSyncErr(err)
	}
	return a.GetState(), nil
}

// Logout 停止所有隧道并清除本地凭据。
//
// 两处顺序上的要求，都是为了避免「用户以为退出了、进程还在跑」：
//
//  1. 必须与同步互斥。后台同步可能正跑在对账中途，它会在本方法停掉进程
//     之后按服务端状态把隧道重新拉起来——凭据已清、进程却还在。
//  2. 必须确认进程都停了再清凭据。停止失败还照样清除登录状态的话，
//     界面上是「已退出」，而 frpc 还在后台占着端口、继续转发。
func (a *App) Logout() (State, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	if err := a.mgr.StopAll(); err != nil {
		return a.GetState(), fmt.Errorf("停止隧道失败，未退出登录: %w", err)
	}

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
	// 清掉已写入的配置记录：换个账号接入后，旧账号的配置文本不该再参与比对。
	a.applied = map[uint]string{}
	// 隧道错误记录与退避状态也一并清掉：换个账号后，旧账号的失败原因会指向
	// 错误的排查方向，而退避时间会让新账号的隧道白白多等一会儿。
	a.tunnelErrs = map[uint]tunnelErr{}
	a.retries = map[uint]*retryState{}
	a.mu.Unlock()

	if err := clearConfig(); err != nil {
		// 内存里的凭据已经清了，但磁盘上那份还在——下次启动会重新读到它。
		// 这必须让用户知道，所以照样推状态、并把错误抛出去。
		a.emitState()
		return a.GetState(), fmt.Errorf("已退出，但本地凭据文件删除失败: %w", err)
	}
	return a.GetState(), nil
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

// StartTunnel 启用一条隧道并立即建立连接。
//
// 两步都不能省，而且顺序不能反：
//   - 先把服务端状态置为 active——它会开放防火墙端口，并让这条隧道
//     出现在后续下发的配置里；
//   - 再为本机拉起这条隧道自己的 frpc 进程。
//
// 反过来（先起进程）拿到的是「隧道还是停用状态」的配置，frps 那边
// 直接拒绝建代理，用户看到的就是「开关打开了却一直连不上」。
func (a *App) StartTunnel(id uint) (State, error) {
	// 整段操作与后台同步互斥。
	//
	// 不互斥的话有一个很难复现的竞态：后台同步先读到「这条隧道已停用」
	// 的清单，用户此刻点了开启，同步随后拿着那份旧清单把刚起来的进程
	// 停掉——用户看到的就是「点了开启，一闪又断了」。
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusActive {
		if err := a.setTunnelStatus(base, apiKey, id, tunnelStatusActive); err != nil {
			return a.GetState(), err
		}
	}
	if err := a.startTunnelProcess(t); err != nil {
		a.noteStartFailure(id, t.Name, "启动失败："+err.Error())
		return a.GetState(), err
	}
	// 用户主动点开：把退避清掉。否则他刚修好问题再点一次，
	// 可能还要等上一次失败留下的退避时间。
	a.clearRetry(id)
	return a.syncAndState(), nil
}

// StopTunnel 断开一条隧道并停用它。
//
// 顺序与 StartTunnel 相反：**先改服务端状态，再停本机进程**。
//
// 这里曾经是先停进程、再请求服务端停用，失败时会静默反转用户的操作：
// 服务端请求失败后状态仍是 active，而下一轮自动同步（≤20 秒）会按服务端
// 状态把进程重新拉起来——用户看到「停用失败」，然后隧道自己又跑起来了，
// 而且找不到是谁干的。
//
// 反过来之后，失败发生在本机进程被停掉之前，提示与实际状态一致；
// 而「服务端已停用、本机进程还在」这种中间态会被下一轮同步收掉，
// 是自愈的。代价是有一瞬间服务端已停用而进程还没停——frpc 可能刷一两行
// 重连错误，比「操作被静默反转」好得多。
func (a *App) StopTunnel(id uint) (State, error) {
	// 与 StartTunnel 同理：必须和后台同步互斥，否则会被旧清单重新拉起来。
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusDisabled {
		if err := a.setTunnelStatus(base, apiKey, id, tunnelStatusDisabled); err != nil {
			return a.GetState(), err
		}
	}
	if err := a.stopTunnelProcess(t); err != nil {
		return a.GetState(), err
	}
	return a.syncAndState(), nil
}

// syncAndState 在**已持有 syncMu** 的前提下对账一次并广播最新状态。
//
// 单独抽出来是因为开关操作需要在同一把锁内完成「改状态 → 起停进程 →
// 重新对账」，中间不能让后台同步插进来；而 Refresh 自己会去抢锁，
// 在锁内调用它就是死锁。
func (a *App) syncAndState() State {
	if _, err := a.applySync(); err != nil {
		a.setSyncErr(err)
	}
	state := a.GetState()
	a.emitState()
	return state
}

// setTunnelStatus 修改隧道在服务端的启用状态。
func (a *App) setTunnelStatus(base, apiKey string, id uint, status string) error {
	payload, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d/status", base, id)
	_, err = a.do(http.MethodPost, endpoint, apiKey, payload)
	return err
}

// findTunnel 在当前隧道清单里找一条隧道。
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
		a.emitState()
		return
	}

	if changed {
		// 明确告知用户「列表变了、已自动跟上」，否则他会疑惑
		// 为什么隧道列表自己动了、某条隧道为什么闪了一下。
		a.emitNotice("检测到隧道变更，已自动同步并重连受影响的隧道")
	}
	a.emitState()
}

// syncLocked 在一次互斥的保护下完成「拉取 → 逐条隧道对账」。
//
// 抽出这个方法而不是让两处各自组合：手动同步和自动同步一旦逻辑分叉，
// 迟早会出现「按钮点的能用、后台同步的不能用」这类难以复现的问题。
func (a *App) syncLocked() (changed bool, err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	return a.applySync()
}

// applySync 拉取隧道清单，并把本机的 frpc 进程对账到服务端说的状态。
//
// 对账规则，每条隧道独立判断：
//
//	服务端启用 + 本机没进程 → 拉起这一条
//	服务端停用 + 本机有进程 → 停掉这一条
//	配置文本变了           → 只重启这一条
//
// 「按隧道独立」是这套实现的关键。早期版本是一份包含全部隧道的配置加
// 单个进程，任何一条隧道的改动都会让整份文本变化，于是所有隧道一起重启
// ——用户看到的就是「改一条隧道，其他全断一下」。
func (a *App) applySync() (changed bool, err error) {
	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if base == "" || apiKey == "" {
		return false, errors.New("尚未接入")
	}

	var data clientInfoData
	if err := a.getJSON(base+"/api/user/client/info", apiKey, &data); err != nil {
		return false, err
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
	a.lastSyncAt = time.Now()
	a.syncErr = ""
	a.mu.Unlock()

	// 复制一份再逐条对账：对账过程要访问网络、写文件、起进程，
	// 全程占着锁会把界面刷新（GetState）一起卡住。
	tunnels := make([]TunnelVO, len(data.Tunnels))
	copy(tunnels, data.Tunnels)

	// 先收掉「服务端已经没有这条隧道」的进程。
	//
	// 这一步必须单独做：下面那个循环只遍历**当前还存在**的隧道，
	// 被删掉的隧道根本不会进入循环，它的进程就会一直留在那里重连。
	// 而界面上已经没有这条隧道了——用户找不到是谁在报错，只能看到
	// frps 一直在刷「隧道不存在」，最后把问题归到认证或防火墙上。
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
		// 隧道都没了，它的失败记录与退避状态一并清掉：
		// 留着只会让这两个 map 随着「建了又删」的隧道缓慢增长。
		a.clearTunnelErr(id)
		a.clearRetry(id)
		changed = true
	}

	// 单条隧道的失败要攒起来，最后作为**部分失败**返回。
	//
	// 以前是只写一行日志、然后照常返回 nil：调用方于是把本轮同步当成
	// 完全成功——SyncErr 被清空、LastSyncAt 被更新，而那条隧道其实没连上。
	// 用户看到的是「一切正常」，隧道却一直不工作。
	var failures []string

	// 记录一次失败。两类失败的**退避**处理不同，所以分成两个函数：
	//
	//   - failSync：同步本身没成（配置拉不到、服务端没返回配置）。
	//     这是网络或服务端的问题，与「这条隧道的进程起不来」无关，
	//     不该推进进程退避——否则配置接口恢复之后，客户端还要为
	//     「每次拉取失败都算一次启动失败」而多等最长 5 分钟。
	//   - failStart：进程起不来。这类才需要退避，避免每 20 秒重复拉起。
	recordFailure := func(t TunnelVO, msg string) {
		a.emitTunnelLog(t.Name, msg)
		// 同时记进该隧道的错误，让隧道行自己把原因显示出来，
		// 而不是只躺在日志里等着被翻出来。
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

	for _, t := range tunnels {
		if t.Status != tunnelStatusActive {
			if a.mgr.Running(t.ID) {
				if err := a.stopTunnelProcess(t); err != nil {
					return changed, err
				}
				changed = true
			}
			continue
		}

		// 退避中的隧道连配置都不用取：反正这一轮不会拉起它。
		// 放在取配置之前，既省掉一次请求，也避免「拉取失败」被误记成
		// 一次启动失败而把退避越推越长。
		if !a.mgr.Running(t.ID) && !a.retryAllowed(t.ID) {
			continue
		}

		cfgText, err := a.fetchTunnelConfig(base, apiKey, t.ID)
		if err != nil {
			// 单条隧道的配置拉不到，不该让整次同步中断——
			// 其他隧道仍然要对账，否则一条坏隧道会拖住全部。
			failSync(t, "拉取配置失败："+err.Error())
			continue
		}
		if cfgText == "" {
			// 空配置必须当成失败，不能静默跳过。
			//
			// 跳过的话这一轮会被记成完全成功（SyncErr 清空、LastSyncAt 更新），
			// 而那条隧道什么都没连上，界面上也没有任何原因——
			// 用户只能看到一个「连接中」，等多久都不会变。
			failSync(t, "服务端未返回该隧道的配置")
			continue
		}

		prev := a.appliedConfigOf(t.ID)
		cfgChanged := cfgText != prev

		switch {
		case !a.mgr.Running(t.ID):
			if err := a.writeAndStart(t, cfgText); err != nil {
				failStart(t, "启动失败："+err.Error())
				continue
			}
			a.clearRetry(t.ID)
			changed = true
		case cfgChanged:
			// 只重启这一条：其他隧道的连接不受影响。
			a.emitTunnelLog(t.Name, "配置有变化（"+diffHint(prev, cfgText)+"），正在重连")
			if err := a.mgr.Stop(t.ID); err != nil {
				return changed, err
			}
			if err := a.writeAndStart(t, cfgText); err != nil {
				failStart(t, "重连失败："+err.Error())
				continue
			}
			changed = true
		}
	}

	if len(failures) > 0 {
		// 只列前两条，避免十几条隧道全挂时把这行日志撑成一大段。
		detail := failures[0]
		if len(failures) > 1 {
			detail = fmt.Sprintf("%s 等 %d 条", failures[0], len(failures))
		}
		return changed, fmt.Errorf("%d 条隧道同步失败：%s", len(failures), detail)
	}
	return changed, nil
}

// ---- 单条隧道的进程 ----

// fetchTunnelConfig 拉取某条隧道专属的配置文本。
//
// 只取这一条：配置文件里只有一条 [[proxies]]，进程之间不会互相干扰。
func (a *App) fetchTunnelConfig(base, apiKey string, id uint) (string, error) {
	var text string
	endpoint := fmt.Sprintf("%s/api/user/client/config?tunnel_id=%d", base, id)
	if err := a.getRaw(endpoint, apiKey, &text); err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// writeAndStart 落盘配置并启动该隧道的 frpc 进程。
//
// 启动成功与否由回调里的日志体现（frpc 会打印自己的连接过程），
// 这里不做额外等待：frpc 从启动到真正建好代理要一两秒，
// 阻塞在界面上等它只会让「连接」这个动作显得很慢。
func (a *App) writeAndStart(t TunnelVO, cfgText string) error {
	path, err := frpcConfigPath(t.ID)
	if err != nil {
		return err
	}
	if err := writeFrpcConfig(t.ID, cfgText); err != nil {
		return err
	}
	// 把配置路径一起打出来：隧道起不来时，第一件要确认的就是
	// 「客户端到底用了哪份配置」，而这份配置是每条隧道一份的。
	a.emitTunnelLog(t.Name, "开始加载隧道配置："+path)
	if err := a.mgr.Start(t.ID, t.Name, path); err != nil {
		return err
	}

	// 记下这次写入的原文。下一次同步据此判断「配置有没有变」——
	// 不记的话每次同步都会判定为变化并重启一遍，连接会一直抖。
	a.mu.Lock()
	a.applied[t.ID] = cfgText
	a.mu.Unlock()
	return nil
}

// startTunnelProcess 为用户主动点「连接」的隧道拉配置并启动。
func (a *App) startTunnelProcess(t TunnelVO) error {
	if a.mgr.Running(t.ID) {
		return nil
	}
	if !a.mgr.Available() {
		return errors.New("未找到 frpc 可执行文件，请将 frpc.exe 放到程序同目录")
	}
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return err
	}
	cfgText, err := a.fetchTunnelConfig(base, apiKey, t.ID)
	if err != nil {
		return err
	}
	if cfgText == "" {
		return errors.New("服务端未返回该隧道的配置")
	}
	return a.writeAndStart(t, cfgText)
}

// stopTunnelProcess 停掉某条隧道的进程。
func (a *App) stopTunnelProcess(t TunnelVO) error {
	a.emitTunnelLog(t.Name, "隧道已断开")
	return a.mgr.Stop(t.ID)
}

// ---- 失败退避 ----

// retryDelay 计算第 n 次失败之后的重试等待。
//
// 起点必须**大于**后台同步周期（20 秒）。比它小的话退避等于不存在：
// 每个同步周期都会重新拉起一次，日志被同样的失败刷屏，而问题一点没变。
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

// retryAllowed 判断这条隧道当前是否允许再次拉起。
func (a *App) retryAllowed(id uint) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	st := a.retries[id]
	return st == nil || time.Now().After(st.nextAt)
}

// noteStartFailure 记一次失败并安排下次重试时间。
func (a *App) noteStartFailure(id uint, name, reason string) {
	a.mu.Lock()
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

	// 把「什么时候再试」说清楚。不说的话，用户只看到反复失败，
	// 分不清客户端是在退避还是已经放弃。
	a.emitTunnelLog(name, fmt.Sprintf("%s（第 %d 次失败，%s 后重试）",
		reason, attempts, delay.Round(time.Second)))
}

// clearRetry 清掉一条隧道的退避状态。
func (a *App) clearRetry(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.retries, id)
}

// countDisabledTunnels 统计当前处于停用状态的隧道。
//
// 停用的隧道不会拉起进程，也不该拉起——但如果日志里只说「0 条隧道运行中」，
// 用户会以为客户端坏了。这个数字用来把「没连」和「不该连」区分开。
func (a *App) countDisabledTunnels() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := 0
	for i := range a.tunnels {
		if a.tunnels[i].Status != tunnelStatusActive {
			n++
		}
	}
	return n
}

// appliedConfigOf 返回某条隧道最近一次写入磁盘的配置原文。
func (a *App) appliedConfigOf(id uint) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.applied[id]
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

// ---- 日志 ----

// emitLog 往运行日志里追加一行客户端自身的说明（不带隧道前缀）。
//
// 与 emitTunnelLog 分开：带前缀的行是「某条隧道发生了什么」，
// 不带前缀的行是「客户端整体在做什么」（启动同步、用时统计）。
// 混在一起会让用户以为启动统计也属于某条隧道。
func (a *App) emitLog(msg string) {
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "log", time.Now().Format("15:04:05")+"  "+msg)
}

// emitTunnelLog 往运行日志里追加一行带隧道前缀的说明。
//
// 前缀格式与 frpc 子进程的输出一致（Tunnel/<名字>），
// 这样「客户端说的话」和「frpc 说的话」在日志里能按隧道对齐——
// 每条隧道一个进程之后，日志是多个进程交织在一起的，
// 没有前缀就分不出哪一行属于哪条隧道。
func (a *App) emitTunnelLog(name, msg string) {
	if a.ctx == nil {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "log",
		fmt.Sprintf("%s  Tunnel/%s  %s", time.Now().Format("15:04:05"), name, msg))
}

// recordTunnelErr 记下一条隧道的 frpc 错误（从原始输出行里取）。
func (a *App) recordTunnelErr(id uint, line string) {
	a.recordTunnelErrMsg(id, frpc.StripLogPrefix(line))
}

// recordTunnelErrMsg 记下一条隧道的错误说明。
//
// 除了 frpc 自己打印的错误，客户端**自己**发现的失败也要记（拉配置失败、
// 进程起不来）：那些失败同样让这条隧道连不上，只写进日志的话，
// 界面上的隧道行仍然什么原因都不显示。
func (a *App) recordTunnelErrMsg(id uint, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunnelErrs == nil {
		a.tunnelErrs = map[uint]tunnelErr{}
	}
	a.tunnelErrs[id] = tunnelErr{msg: msg, at: time.Now()}
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

// GetLogs 返回日志快照。
func (a *App) GetLogs() []string {
	return a.mgr.Logs()
}

// ClearLogs 清空日志缓冲。
func (a *App) ClearLogs() {
	a.mgr.ClearLogs()
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

func writeFrpcConfig(tunnelID uint, text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("服务端返回的配置为空")
	}
	path, err := frpcConfigPath(tunnelID)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("写入客户端配置失败: %w", err)
	}
	return nil
}
