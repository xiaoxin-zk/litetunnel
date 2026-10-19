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

	// PendingSeconds 是「进程已启动、代理还没注册成功」已经等了多久（秒）。
	//
	// 只为诊断而存在：frpc 既没成功也没报错时，界面只能显示「连接中」，
	// 用户分不清是刚起步还是卡了十分钟。0 表示不在连接中（已注册或未启动）。
	PendingSeconds int `json:"pending_seconds,omitempty"`

	// LastError 是最近一次从该隧道的 frpc 输出里识别到的错误原文。
	//
	// 为什么需要它：「连接中」这个状态本身不说明任何原因——凭据失效、
	// 服务地址不对、网络不通都会停在它上面，用户只能干等。把 frpc 自己
	// 报的错摆出来，才能立刻区分是配置问题还是网络问题。
	LastError   string     `json:"last_error"`
	LastErrorAt *time.Time `json:"last_error_at"`

	// ConfigRev 是服务端为该隧道配置算出的摘要(渲染结果的哈希)。
	//
	// 客户端用它跳过没变化的配置请求:摘要一致就说明服务端此刻会生成的字节
	// 与本地缓存的一模一样,再发一次请求只是白等一个往返。隧道一多,这些
	// 逐条隧道的 GET 正是每轮同步耗时的主要部分。
	// 老服务端不下发这个字段(空串),此时按「不知道」处理,照常拉取。
	ConfigRev string `json:"config_rev,omitempty"`
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

	// LogEpoch 是日志命名空间的代次（每次清空日志时递增）。
	//
	// 前端拿它做「跨账号丢弃」：退出登录会清空日志并递增代次，而清空之前
	// 已经发出、清空之后才到达前端的那一批日志事件，前端无法自行分辨
	// ——它们带着旧代次，据此直接丢弃，界面就不会在换账号后先冒出一段
	// 上一个账号的日志。
	//
	// 挂在 State 里而不是只在日志事件里带：登录态变化时前端收到的第一个
	// 权威值就是这份状态，不用等到下一批日志才知道代次变了。
	LogEpoch uint64 `json:"log_epoch"`

	// StateSeq 是**状态事件**的单调序号，每推一次状态递增一次。
	//
	// # 为什么日志代次不够用
	//
	// LogEpoch 保护的是日志批次，它只在「清空日志」时前进。登录态本身没有
	// 任何序号，于是下面这条路径会闪：
	//
	//  1. 用户点退出登录，logout 停进程、翻代次、清凭据、推了一份
	//     logged_in=false 的状态；
	//  2. 但某个隧道进程的退出回调还在协程里没跑完（logout 只等到
	//     logoutCallbackWait 的上限，超时就继续往下走）；
	//  3. 那个回调里调了一次 emitState —— 它读到的是**当时**的 a.cfg；
	//     回调若跑在「清凭据之前」的快照上，推出去的就是 logged_in=true；
	//  4. 前端无条件 applyState，界面在用户已经退出之后又闪回一次已登录
	//     界面（随后被下一次状态推送纠正）。
	//
	// 这与日志混代次是同一类问题：**跨进程事件是异步的，接收端无法自行
	// 判断先后**。区别在于状态事件更"重"——它决定整个界面显示登录页还是
	// 主界面，闪一下比日志混入一行刺眼得多。
	//
	// # 为什么是「每次 emit 都递增」而不是「每次状态变化才递增」
	//
	// 状态内容不变时也可能需要一次推送（例如前端重挂载后的重新对齐）。
	// 让序号跟着**推送次数**走，判据就变成「这份 payload 是不是在我已经
	// 见过的那份之后发出的」，与内容是否相同无关，前端只需一个单调比较。
	//
	// 前端丢弃规则：payload.state_seq < 本端已接受的最大值 → 丢弃。
	// 相等则接受（同一次推送可能因重连被投递两次，重复应用同一份状态无害）。
	StateSeq uint64 `json:"state_seq"`

	// AuthGen 是这份状态所属的**账号代次**（与 StateSeq 一起构成排序键）。
	//
	// # 为什么光有序号还不够
	//
	// StateSeq 只能保证「序号大的后发出」，它管不了「谁先取号」。退出登录
	// 与一个迟到的隧道退出回调是两个协程，可能的交错是：
	//
	//  1. 回调取号 → 拿到 7，但还没走到 EventsEmit（被调度走）；
	//  2. logout 取号 → 拿到 8，推 logged_in=false，前端接受；
	//  3. 回调回来，推序号 7 的 payload —— 前端按序号判旧，丢弃。
	//
	// 这条路径没问题。真正漏的是反向交错：回调**在登出之后**才取号，
	// 于是拿到 9，序号比登出的 8 还大，前端照单全收，把 logged_in=true
	// 推回界面。序号本身无法表达「这份状态属于上一个账号」——它只反映
	// 推送时刻，不反映**内容属于谁**。
	//
	// AuthGen 补上这一维：登出/接入都会让 authGeneration 前进，而回调
	// 持有的账号代次在它启动那一刻就定死了（见 startGen）。前端按
	// (auth_gen, state_seq) 字典序比较：
	//   - auth_gen 更小 → 整份丢弃（它属于旧账号，无论序号多大）；
	//   - auth_gen 相等 → 再比 state_seq；
	//   - auth_gen 更大 → 接受（换了账号，序号基线重来）。
	//
	// 这样「旧账号的迟到事件」无论何时到达都进不来，而不是靠运气赶在
	// 登出推送之前。
	AuthGen uint64 `json:"auth_gen"`
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

	// cfgRev 记录 applied 里那份文本对应的服务端配置摘要(见 TunnelVO.ConfigRev)。
	//
	// 两者必须一起记账:只存文本的话,下一轮无法判断「服务端现在会生成的
	// 字节是否还是这一份」,只能照旧为每条隧道发一次请求。摘要与文本同源
	// (来自同一次响应),所以「摘要相同」等价于「文本相同」。
	// 与 applied 一样由 a.mu 保护。
	cfgRev map[uint]string

	// syncGate 串行化同步操作。后台定时同步与用户的开关操作可能同时发生，
	// 两者都会写配置文件、起停进程；重叠执行会让同一时刻出现
	// 「刚停掉又被拉起来」的反复闪断。
	//
	// 用容量 1 的 channel 而不是 sync.Mutex：等待必须是**可取消**的。
	// 自动同步可能占着它几十秒（逐条拉配置），用户在此期间点创建/删除/
	// 退出登录；不可取消的 Mutex 只能干等到同步结束——预算提前开始计时
	// 也没有意义，因为请求根本还没发出去。
	//
	// 取用一律走 lockSync / unlockSync，不要在别处直接读写。
	syncGate chan struct{}
	gateOnce sync.Once

	// authMu 串行化「凭据的写盘与发布」：接入（Connect）与退出（Logout）
	// 都会改 a.cfg 并写配置文件，交错执行会出现「界面已登录、磁盘上没有
	// 凭据」——重启后凭空丢号。
	//
	// 锁序统一为 syncMu → authMu → mu，磁盘清理也在 authMu 内。
	authMu sync.Mutex

	// authGeneration 由 mu 保护，使登出或重新接入前发起的请求不能发布旧凭据。
	authGeneration uint64

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

	// connectAt 记录每条隧道「本次连接开始」的时刻（见 markConnectStart）。
	//
	// 用来诊断「进程活着但一直没注册成功」：没有起点的话，界面只能一直显示
	// 「连接中」，用户分不清是刚起步还是已经卡了很久。
	connectAt map[uint]time.Time

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
	logBuf      []pendingLog
	logBufBytes int
	logDropped  int

	// logEpoch 在每次清空时递增，随推送事件一起下发。
	//
	// 跨进程事件是异步的：清空之前已经发出、清空之后才到达前端的那一批，
	// 前端无法自行分辨。带上代次之后，旧代次的事件直接被丢弃。
	logEpoch uint64
	// logDroppedSeq 是清空时的日志序号：序号不大于它的在途行属于清空前的
	// 内容，不再入队。仅靠代次挡不住「行已入队、尚未推送」的情况。
	logDroppedSeq uint64
	// logKick 容量 1 的「立刻推送」信号：攒满一批时用它跳到下一轮推送，
	// 不排队也不阻塞——推送协程醒来时取走一批（maxLogBatch 行）。
	logKick chan struct{}
	// logStop 在退出时通知日志推送协程停止，避免窗口销毁后它还继续
	// 调用 EventsEmit；logStopOnce 保证只关闭一次，logWg 让关闭流程
	// 等到它真正退出再返回（见 startLogFlusher / shutdown）。
	logStop     chan struct{}
	logStopOnce sync.Once
	logWg       sync.WaitGroup

	// retries 记录每条隧道连续失败次数与下次允许拉起的时间。
	//
	// 没有它的话：frpc 因凭据失效、地址写错等原因立刻退出，下一轮同步
	// （20 秒后）发现进程不在就再拉一次——如此循环，日志每 20 秒重复一遍
	// 同样的错误，而问题一点没变，用户还以为客户端在「努力重连」。
	retries map[uint]*retryState

	// startGen 记录每条隧道的进程是在哪个**账号代次**下启动的
	// （值取自 a.authGeneration，与它一同由 a.mu 保护）。
	//
	// 退出登录的顺序是「停进程 → 等回调落地 → 翻代次 → 清凭据」，而进程的
	// 退出回调是另一个协程里异步执行的：StopAll 只保证进程真的退出，不保证
	// 回调用完。没有这份记录，一个在登出清理之后才跑到的回调会照着旧进程的
	// 结局去改**新账号**的运行态——把刚连上的隧道标成未连接、或替新账号推进
	// 一次退避，而它描述的那个进程早就跟当前账号无关了。
	//
	// 记的是「启动那一刻的代次」，不是「当前代次」：判据必须是
	// 「启动它的那个账号还是现在这个账号吗」。
	startGen map[uint]uint64

	// cfgErr 记录本地配置读取失败的原因，通过 State 呈现给用户。
	cfgErr string

	// stateSeq 是状态事件序号，由 a.mu 保护（见 State.StateSeq）。
	//
	// 放在 App 上而不是每次 emit 时读 GetState 的返回值再自增：序号必须
	// 在**发出事件之前**就定下来，且要和这份 payload 里的其它字段取自
	// 同一个时刻。先取快照再自增、然后下发，顺序是：
	//   seq := a.nextStateSeq()   // 持锁自增
	//   st := a.GetState()        // 持读锁取快照
	//   st.StateSeq = seq
	//   EventsEmit(...)
	//
	// 两个锁操作之间有极小窗口（另一次 emit 可能插进来先取到更大的序号，
	// 但它也会先发出事件）。这对前端是安全的：前端只按序号单调丢弃，
	// 乱序到达时**后发的那份**序号更大、一定被接受，最终停在最新状态上。
	stateSeq uint64
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
		cfgRev:       map[uint]string{},
		tunnelErrs:   map[uint]tunnelErr{},
		retries:      map[uint]*retryState{},
		registered:   map[uint]bool{},
		registeredAt: map[uint]time.Time{},
		connectAt:    map[uint]time.Time{},
		errEmitAt:    map[uint]time.Time{},
		startGen:     map[uint]uint64{},
		logKick:      make(chan struct{}, 1),
		logStop:      make(chan struct{}),
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
	a.mgr.SetGenerationCallbacks(func(id uint, name string, gen uint64, seq uint64, line string) {
		// 日志回调在 Manager 内排队，旧进程的行可能晚于新进程到达。
		// 只有当前 generation 才能修改注册、退避和错误状态；旧日志仍保留
		// 用于诊断，但不再污染当前隧道运行态。
		// 先判代次再落日志：旧账号进程迟到的行不属于当前账号，既不能改
		// 状态也不能进日志缓冲——否则用户换了账号，界面上会先冒出上一段
		// 会话的输出。Manager 已在入队前做过一次同样的过滤，这里是回调
		// 排队期间又发生切换时的第二道。
		if !a.mgr.Current(id, gen) {
			return
		}
		a.appendLogLine(seq, line)
		switch {
		case strings.Contains(line, "start proxy success"):
			// frpc 报告代理启动成功时补一条「现在可以用这个地址了」。
			// 原始输出只有一行 start proxy success，用户看不出这意味着
			// 「可以把地址发给朋友了」——而那恰恰是他最需要的信息。
			a.clearTunnelErrGen(id, gen)
			// 连上了就把退避清掉：下次断开时应当立即重试，
			// 而不是继承上一次失败的等待时间。
			a.clearRetryGen(id, gen)
			// 立刻把这条隧道标成「已注册」并推一次状态。
			//
			// 服务端的 Online 要等采集（30 秒一轮）+ 客户端同步（20 秒一轮），
			// 用户会盯着「连接中」等一整轮，误以为连不上；而 frpc 此刻已经
			// 报告成功了，没有理由让他等。服务端采集值仍用于后续校准。
			a.setTunnelRegisteredGen(id, gen, true)
			a.emitTunnelReady(id, name)
			a.emitState()
		case frpc.IsErrorLine(line):
			// 记下错误原文并刷新状态，让界面能显示「为什么一直连不上」，
			// 而不是永远停在一句「连接中」上。
			//
			// 但只在错误原文**变化**时刷新，并对同一隧道限频：一次连接失败
			// 可能瞬间刷出上千行同样的错误，逐行推状态纯属浪费（每推一次都
			// 要序列化整个状态），而重复的错误对用户没有新信息。
			if a.recordTunnelErrMsgGen(id, gen, line) {
				a.emitStateThrottled(id)
			}
		}
	}, func(id uint, name string, gen uint64, err error, requested bool) {
		if !a.mgr.Current(id, gen) {
			return
		}
		a.onTunnelExitGen(id, name, gen, err, requested)
	})
}

// onTunnelExit 处理「某条隧道的 frpc 进程退出」。
//
// 单独抽成方法（而不是留在 startup 的闭包里）是为了让它能被单测直接调用：
// 这段逻辑守的是「退出登录与迟到回调」的竞态，靠真起进程去复现既慢又不稳，
// 而它要判断的东西全在 a 的状态里。
func (a *App) onTunnelExit(id uint, name string, err error, requested bool) {
	a.onTunnelExitGen(id, name, 0, err, requested)
}

func (a *App) onTunnelExitGen(id uint, name string, gen uint64, err error, requested bool) {
	// 先核对这条隧道是不是**当前账号**启动的。
	//
	// 退出登录的顺序是「停进程 → 等回调 → 翻代次 → 清凭据」，但等待是有
	// 上限的：超时后流程照常往下走，那个回调可能仍会在新账号下才执行。
	// 它描述的是一个属于上一个账号的进程，而下面每一行写的都是**当前**
	// 账号的运行态：清掉 registered 会把新账号刚连上的隧道标成未连接，
	// noteStartFailure 会给新账号记一笔它没犯过的失败并推进退避，
	// emitState 会把这份污染推给界面。
	//
	// 所以代次不符时只做无副作用的收尾：什么都不写、什么也不发。
	// startGeneration 自带 a.mu，这里不持锁调用任何 mgr 方法，
	// 也就不会与 exitMu → mu 的既有顺序冲突。
	//
	// 不在这里删自己那条记账：它的值就是账号代次，同一账号下的下一次
	// 启动会写出同一个值，删错就把下一次的记录抹掉了（详见
	// startGeneration 的说明）。条目由 pruneTunnelState 与
	// resetPerAccountState 负责回收。
	if _, current := a.startGeneration(id); !current {
		// 记录已被清掉（退出登录或隧道被删）时同样落到这里：那也
		// 说明「无法证明它属于当前账号」，按不处理即可——
		// 下一轮同步会据实对账，甚至已经把这条隧道停掉了。
		return
	}
	// 进程没了，代理自然也不在——无论是我们主动停的还是它自己退出的。
	// 不清的话，界面会一直显示「运行中」，而实际上这条隧道已经断了。
	a.setTunnelRegisteredGen(id, gen, false)
	switch {
	case requested:
		// 我们自己停的（用户关开关、退出登录、配置变更重连）：
		// 不是失败，不该进入退避——否则用户关掉一条隧道，
		// 界面反而开始报「启动失败，30 秒后重试」。
		a.clearRetryGen(id, gen)
	default:
		// 非请求退出都算失败并进入退避，包括 err == nil 的情况：
		// frpc 自己干净退出同样意味着这条隧道没在跑，不加退避就会
		// 每 20 秒被重新拉起一次。
		reason := "frpc 已退出"
		if err != nil {
			reason = "frpc 异常退出：" + err.Error()
		}
		a.noteStartFailureGen(id, gen, name, reason)
	}
	a.emitState()
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
		//
		// 用可取消的等待而不是 time.Sleep：窗口在此期间被关掉时直接返回，
		// 不要等延迟结束再发一次同步、再推一轮状态事件。
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-a.rootContext().Done():
			return
		case <-timer.C:
		}

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
			// 这里刻意用不可取消的等待：关闭流程要确认的就是「那一轮同步
			// 真的收工了」，超时放弃会让它失去意义（下面另有总超时兜底）。
			a.lockSyncBlocking()
			a.unlockSync()
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

	// 停止日志推送协程：先关信号、等它退出，最后再推一次兜底。
	//
	// mgr.Close（上面）会产出「隧道已断开」「frpc 已退出」等收尾日志，这些行
	// 已经进入队列，flusher 收到停止信号后会先把它们推出去再退出。这里最后
	// 再 flush 一次，覆盖 flusher 尚未启动（如测试直接构造的 App）等边缘情况。
	// 关信号必须在等退出之前：不关的话 logWg.Wait 会永远等不到。
	if a.logStop != nil {
		a.logStopOnce.Do(func() { close(a.logStop) })
		a.logWg.Wait()
	}
	// 把队列里剩下的日志推出去：停止进程会产出「隧道已断开」「frpc 已退出」
	// 这类收尾日志，攒在队列里不发，用户下次打开客户端时日志就断在退出前。
	a.flushLogs()
}

// OpenDataDir 在资源管理器中打开数据目录。
func (a *App) OpenDataDir() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", dir)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	// 失败必须报给界面：只返回目录的话，用户点了按钮什么都没发生，
	// 也看不到原因（没有文件管理器、被策略禁用等）。
	if err := cmd.Start(); err != nil {
		return dir, fmt.Errorf("打开数据目录失败: %w", err)
	}
	return dir, nil
}
