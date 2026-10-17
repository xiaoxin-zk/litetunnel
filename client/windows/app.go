package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	// Running 表示本机是否已为这条隧道拉起 frpc 进程。
	//
	// 与 Online 的区别必须分清：Online 是服务端视角（隧道是否已注册到
	// frps），Running 是本机视角（进程在不在）。界面上的开关看的是
	// Running——用户点的是「我这台机器上要不要连出去」。
	Running bool `json:"running"`

	// Registered 表示 frpc 已报告这条代理注册成功（本机视角，立即生效）。
	//
	// 为什么需要它：Online 来自服务端采集（默认 30 秒一轮），客户端同步又是
	// 20 秒一轮，所以「frps 已经收到这条代理」要过最多约 50 秒才反映到界面上
	// ——用户点完连接会盯着「连接中」等一整轮，误以为连不上。
	//
	// 而 frpc 自己会在 200 毫秒内报出 `start proxy success`，客户端解析到这行
	// 就能立刻把标签切成「运行中」。服务端采集值继续用于后续校准（代理掉线、
	// 隧道被服务端停用等情况仍以它为准）。
	Registered bool `json:"registered"`

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
	applied    map[uint]string
	lastSyncAt time.Time
	syncErr    string

	// syncMu 串行化同步操作。后台定时同步与用户的开关操作可能同时发生，
	// 两者都会写配置文件、起停进程；重叠执行会让同一时刻出现
	// 「刚停掉又被拉起来」的反复闪断。
	syncMu sync.Mutex

	// syncStart 是下一轮同步从清单的哪个位置开始处理（见 applySyncData）。
	//
	// 服务端清单按 id 倒序返回，配置又是「并发 6 条 + 整轮 45 秒截止」：
	// 若每轮都从清单开头开始，前面几条一旦持续超时，后面的隧道永远轮不到
	// ——客户端重启也不会变，因为它们仍在同一位次。记下上一轮处理到哪儿、
	// 下一轮从那里环形开始，被截止时间砍掉的尾部自然排到最前面。
	// 由 syncMu 保护。
	syncStart int

	// syncRoot 是同步用的根上下文，退出时由 syncCancel 取消。
	//
	// 各轮同步自己带 context.Background() 起截止时间的话，关窗口**取消不了**
	// 在途的清单/配置请求：进程一边在退出，一边还有一轮同步在跑，它可能在
	// StopAll 之后才拿到配置并把 frpc 拉起来。Job Object 能兜住异常退出，
	// 但它绑定失败时（见 frpc.Manager.Start 的提示）那就是一个真正的孤儿进程。
	// 所以退出流程固定为「取消同步 → 等这一轮退出 → 关闭并停全部进程」。
	syncRoot   context.Context
	syncCancel context.CancelFunc

	// closeDone 保证退出清理只执行一次（窗口可能触发多次关闭事件）。
	closeDone sync.Once

	// syncSeq 发放给每次拉取到的清单快照，appliedSyncSeq 记录已应用的最大
	// 序号（由 syncMu 保护）。
	//
	// 接入流程与后台同步各自拉清单：接入先拉、后台后拉，但后台可能先应用。
	// 若接入随后把旧清单应用上去，会把它拉取之后才新建的隧道当成「服务端
	// 已删除」而停掉进程、删掉配置——下一轮同步才恢复。序号让过期快照
	// 被直接拒绝（见 syncWithData）。
	syncSeq        atomic.Uint64
	appliedSyncSeq uint64

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

	// cleanupWarned 记录已经就「本地配置清理失败」提示过用户的隧道，
	// 避免每轮同步（20 秒）都重复弹同一条提示。
	cleanupWarned map[uint]bool

	// registered 记录 frpc 已报告注册成功的隧道（见 TunnelVO.Registered）。
	// 由 start proxy success 置位，进程退出/主动停止/重新拉起时清掉。
	registered map[uint]bool

	// registeredAt 记录 registered 置位的时刻，用于「宽限期」校准。
	//
	// 标记本身只是一行日志的产物，是**瞬时**结论：进程不退出它就永远为真，
	// 哪怕 frps 重启过、代理早被踢掉、frpc 正在无限重连。服务端的 online
	// 才是权威，但它有延迟（采集 30 秒一轮 + 同步 20 秒一轮），所以只能
	// 「先信本机、过了宽限期再信服务端」——没有这个时间戳就无从判断
	// 「服务端说离线」到底是它还没采到，还是这条隧道真的掉了。
	registeredAt map[uint]time.Time

	// errEmitAt 是「上一次因错误推送状态」的时间，用于限频。
	//
	// frpc 的日志现在走 console，一次连接失败可能瞬间刷出上千行错误；每行都
	// 推一次状态意味着反复序列化整个状态再发给前端。这里对同一隧道限到 1 秒
	// 一次，重复的错误对用户没有新信息。
	errEmitAt map[uint]time.Time

	// logMu / logBuf / logKick 是日志的批量推送队列，见 pushLog。
	//
	// 不直接逐行 EventsEmit 的原因：frpc 出错时会瞬间刷出上千行，
	// 每行一次 Wails 调用都要跨进程、序列化、唤醒 JS，这条桥会被堵住，
	// 反过来把读取管道的协程也拖慢（管道写满后子进程跟着阻塞）。
	//
	// logBuf 有容量上限（maxLogQueue）：前端消费慢于生产时队列会一直涨，
	// 而日志洪峰恰恰出现在客户端出问题的时候——那时最不该再把内存吃光。
	// 触顶时丢弃最旧的并累计到 logDropped，下一次推送会明确告知丢了多少。
	logMu sync.Mutex
	// logBufBytes 是 logBuf 的总字节数：行数上限挡不住「每行都很长」，
	// 两份预算一起用（见 maxLogQueueBytes）。
	logBuf      []string
	logBufBytes int
	logDropped  int
	// logKick 容量 1 的「立刻推送」信号：攒满一批时用它跳到下一轮推送，
	// 不排队也不阻塞——推送协程醒来时取走一批（maxLogBatch 行）。
	logKick chan struct{}

	// retries 记录每条隧道连续失败次数与下次允许拉起的时间。
	//
	// 没有它的话：frpc 因凭据失效、地址写错等原因立刻退出，下一轮同步
	// （20 秒后）发现进程不在就再拉一次——如此循环，日志每 20 秒重复一遍
	// 同样的错误，而问题一点没变，用户还以为客户端在「努力重连」。
	retries map[uint]*retryState

	// cfgErr 记录本地配置读取失败的原因，通过 State 呈现给用户。
	cfgErr string
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

	// 同步的根上下文：应用退出时由 shutdown 取消（见 App.syncRoot）。
	syncCtx, syncCancel := context.WithCancel(context.Background())

	app := &App{
		cfg:          cfg,
		mgr:          frpc.New(exePath),
		syncRoot:     syncCtx,
		syncCancel:   syncCancel,
		applied:      map[uint]string{},
		tunnelErrs:   map[uint]tunnelErr{},
		retries:      map[uint]*retryState{},
		registered:   map[uint]bool{},
		registeredAt: map[uint]time.Time{},
		errEmitAt:    map[uint]time.Time{},
		logKick:      make(chan struct{}, 1),
		startedAt:    time.Now(),
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
	// 日志出的第一行就进批量队列：只要开始产生日志，推送到前端的节奏就
	// 由推送协程决定，而不是「一行一次 Wails 调用」。
	a.startLogFlusher()
	a.mgr.SetCallbacks(func(id uint, name, line string) {
		a.appendLogLine(line)
		switch {
		case strings.Contains(line, "start proxy success"):
			// frpc 报告代理启动成功时补一条「现在可以用这个地址了」。
			// 原始输出只有一行 start proxy success，用户看不出这意味着
			// 「可以把地址发给朋友了」——而那恰恰是他最需要的信息。
			a.clearTunnelErr(id)
			// 连上了就把退避清掉：下次断开时应当立即重试，
			// 而不是继承上一次失败的等待时间。
			a.clearRetry(id)
			// 立刻把这条隧道标成「已注册」并推一次状态。
			//
			// 服务端的 Online 要等采集（30 秒一轮）+ 客户端同步（20 秒一轮），
			// 用户会盯着「连接中」等一整轮，误以为连不上；而 frpc 此刻已经
			// 报告成功了，没有理由让他等。服务端采集值仍用于后续校准。
			a.setTunnelRegistered(id, true)
			a.emitTunnelReady(id, name)
			a.emitState()
		case frpc.IsErrorLine(line):
			// 记下错误原文并刷新状态，让界面能显示「为什么一直连不上」，
			// 而不是永远停在一句「连接中」上。
			//
			// 但只在错误原文**变化**时刷新，并对同一隧道限频：一次连接失败
			// 可能瞬间刷出上千行同样的错误，逐行推状态纯属浪费（每推一次都
			// 要序列化整个状态），而重复的错误对用户没有新信息。
			if a.recordTunnelErr(id, line) {
				a.emitStateThrottled(id)
			}
		}
	}, func(id uint, name string, err error, requested bool) {
		// 进程没了，代理自然也不在——无论是我们主动停的还是它自己退出的。
		// 不清的话，界面会一直显示「运行中」，而实际上这条隧道已经断了。
		a.setTunnelRegistered(id, false)
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

// shutdownSyncWait 是退出时等待在途同步收工的上限。
//
// 取 3 秒：一轮同步的网络请求都会被 syncCancel 立刻打断，正常情况下只需
// 几毫秒；留这点余量是为了偶尔在写磁盘、起停进程上多花的时间，再长就
// 等于让用户盯着一个关不掉的窗口。
const shutdownSyncWait = 3 * time.Second

// shutdown 在客户端退出前被调用，确保所有 frpc 子进程一并结束。
//
// 顺序有讲究：**取消同步 → 等这一轮退出 → 关闸并停全部进程**。
//
// 只调 StopAll 不够：同步用的是自己的根上下文（见 App.syncRoot），
// 关窗口并不会让它停下来。它可能正好在 StopAll 之后才拿到配置，把 frpc
// 重新拉起来——这次关停就漏掉了那个进程。Job Object 通常能兜住（父进程
// 退出时连带结束子进程），但它绑定失败时（见 frpc.Manager.Start 的提示）
// 就是一个真正的孤儿进程：端口仍被占着，隧道仍在转发。
//
// 异常退出（崩溃、被任务管理器强杀、系统关机时的强制终止）走不到这里，
// 由 Job Object 兜底——两者是互补关系，缺任何一层都会留下孤儿进程。
func (a *App) shutdown(ctx context.Context) {
	a.closeDone.Do(func() {
		// 取消在途的清单/配置请求，下面的等待才有上界。
		if a.syncCancel != nil {
			a.syncCancel()
		}

		// 等到「没有同步在跑」为止：syncMu 是整轮同步的临界区，
		// 拿得到它就意味着那一轮已经收工，不会再拉起新进程。
		// 带超时是因为关闭流程不能无限期卡住——真有异常停滞时，
		// 下面 Manager.Close 关掉的那个闸门仍然挡得住迟到的启动。
		done := make(chan struct{})
		go func() {
			a.syncMu.Lock()
			a.syncMu.Unlock()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownSyncWait):
			log.Printf("[client] 退出时等待同步结束超时（%s），继续停止 frpc", shutdownSyncWait)
		}

		// 先关闸、再停进程：Close 之后任何 Start 都会直接失败，
		// 即便上面等超时了，也不会有新进程漏在 StopAll 之后。
		if err := a.mgr.Close(); err != nil {
			log.Printf("[client] 退出时停止 frpc 失败: %v", err)
		}
	})

	// 把队列里剩下的日志推出去：停止进程会产出「隧道已断开」「frpc 已退出」
	// 这类收尾日志，攒在队列里不发，用户下次打开客户端时日志就断在退出前。
	a.flushLogs()
}

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
		tunnels[i].Registered = a.registered[tunnels[i].ID]
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
