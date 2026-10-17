package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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

// syncInterval 是两轮后台同步之间的间隔（从**上一轮结束**算起）。
//
// 不是「固定节拍」：一轮最长 45 秒，用固定 ticker 会积压信号，
// 导致这轮刚结束就立刻开始下一轮（见 startAutoSync）。
//
// 取 20 秒是折中：用户在网页端加完隧道再切回客户端，基本已经同步好了；
// 而每次同步是「一次接入信息 + 每条隧道一次配置」的轻量 GET（配置那几个
// 并发发出、且有上限，见 configFetchConcurrency），不会给服务端造成压力。
const syncInterval = 20 * time.Second

// configFetchConcurrency 是同一轮同步里并发拉取隧道配置的上限。
//
// 取 6 是折中：隧道数量通常是个位数，6 路并发就能把「隧道数 × 往返时间」
// 压成接近「一两轮往返」；再往上加，收益会被本机与家用带宽吃光，
// 反而更容易触发服务端的限流。
const configFetchConcurrency = 6

// syncRoundTimeout 是整轮同步中配置拉取阶段的截止时间。
//
// 为什么需要它：同步持有 syncMu，启动/停止/退出等手动操作都要等这一轮
// 跑完。单次请求有 15 秒超时兜底，但「隧道数 × 单次超时 / 并发数」会随
// 隧道数量无界增长——几十条隧道加一个不通的服务器地址，能把手动操作
// 挡上几分钟。整轮限时后，超时的部分留给下一轮自动重试（对账本来就是
// 幂等的，漏掉的隧道下一轮会补上）。
// 用变量而不是常量：测试里要把它压短来复现超时路径。
var syncRoundTimeout = 45 * time.Second

// startAutoSync 启动后台自动同步，随应用退出而结束。
//
// 为什么必须有它：用户完全可能在网页控制台里加一条隧道，
// 而客户端此刻正在运行。没有自动同步的话，他必须手动点「同步配置」，
// 更糟的是——即使点了，运行中的 frpc 也不会加载新配置，
// 于是「隧道明明建好了却连不上」，用户只会认为产品坏了。
func (a *App) startAutoSync(ctx context.Context) {
	go func() {
		// 用「上一轮结束后再等 20 秒」而不是固定 ticker。
		//
		// ticker 会在一轮没收工时先攒下一个信号：一轮最长 45 秒，等于攒了
		// 两个，这轮一结束就立刻开始下一轮——慢服务器或隧道多的时候，客户端
		// 会连着不停地发同步请求，而每一轮本来就已经压在 45 秒上限上了。
		timer := time.NewTimer(syncInterval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			a.autoSyncOnce()
			timer.Reset(syncInterval)
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

// nextSyncSeq 给刚拉到的清单快照发一个单调序号。
func (a *App) nextSyncSeq() uint64 {
	return a.syncSeq.Add(1)
}

// syncWithData 与 syncLocked 相同，但接入流程已经拿到过一份 client/info
// 响应时，直接把它交给同步，省掉一次重复的网络往返。
//
// seq 是那份快照的序号（见 nextSyncSeq）。接入流程的拉取发生在拿到
// syncMu **之前**：期间后台同步可能已经拉到并应用了更新的清单。若这里
// 照旧应用旧快照，会把新清单里的隧道当成「已删除」而停掉进程。序号更小
// 的过期快照一律不应用，改为重新拉一轮——这时的目标就是「把本机对齐到
// 最新状态」，重拉一次最直接，也省得区分哪些差异是过期造成的。
func (a *App) syncWithData(data *clientInfoData, seq uint64) (changed bool, err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	if seq <= a.appliedSyncSeq {
		return a.applySync()
	}
	ctx, cancel := a.newSyncContext()
	defer cancel()
	return a.applySyncData(ctx, data, seq)
}

// newSyncContext 为一轮同步创建带截止时间的上下文。
//
// 根上下文是 a.syncRoot 而不是 context.Background()：应用退出时它会被
// 取消（见 App.shutdown），这一轮正在跑的清单/配置请求立刻返回，退出流程
// 才等得到 syncMu——等不到就拿不到「不会再有新进程被拉起」的保证。
// 测试里直接构造 App 时没有根上下文，退回 Background。
func (a *App) newSyncContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.rootContext(), syncRoundTimeout)
}

// rootContext 是所有客户端请求的根上下文：应用退出时被取消（见 App.shutdown）。
// 测试里直接构造 App 时没有它，退回 Background。
func (a *App) rootContext() context.Context {
	if a.syncRoot != nil {
		return a.syncRoot
	}
	return context.Background()
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
		return false, errors.New(a.baseReason())
	}

	// 整轮共用一个截止上下文：接入信息（可能还要分页）与后续的配置拉取
	// 都在同一笔预算里。只给配置拉取限时的话，前面那几次请求仍可各自
	// 等满超时，手动操作被挡的总时长并没有真正封顶。
	// 根上下文随应用退出而取消，见 newSyncContext。
	ctx, cancel := a.newSyncContext()
	defer cancel()

	data, err := a.fetchClientInfo(ctx, base, apiKey)
	if err != nil {
		return false, err
	}
	// 本轮在 syncMu 内拉取，序号必然最新（见 nextSyncSeq 的说明）。
	return a.applySyncData(ctx, data, a.nextSyncSeq())
}

// applySyncData 执行对账。data 是本轮要采纳的接入信息快照——
// 正常路径来自刚请求的 /client/info，接入路径来自 Connect 已验证
// Key 有效的同一次响应。ctx 是本轮的截止上下文（见 syncRoundTimeout），
// 已消耗的时间计入同一笔预算。
//
// seq 是快照的单调序号：比已应用的更旧就整份丢弃（调用方须持有 syncMu）。
// 过期清单绝不能参与对账——它会停掉拉取之后才新建的隧道。
func (a *App) applySyncData(ctx context.Context, data *clientInfoData, seq uint64) (changed bool, err error) {
	if seq <= a.appliedSyncSeq {
		return false, nil
	}
	a.appliedSyncSeq = seq

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
		changed = true
	}
	// 按「服务端当前有哪些隧道」清一遍记录，而不是只看运行中的进程。
	//
	// 只看进程会漏掉一类：隧道因为启动失败而没有进程，随后被服务端删掉——
	// 它的错误与退避记录再也不会被访问到。反复「建了、失败、删掉」
	// 会让这两个 map 一直长下去。
	a.pruneTunnelState(alive)

	// 再清掉它们在本地留下的配置文件。
	//
	// 只清内存是不够的：frpc.toml 里含客户端接入密钥与 frps token，隧道已经在
	// 服务端删掉（可能是在网页端删的），磁盘上那份却仍然可以被任何能读到该
	// 目录的进程拿去接入。
	a.cleanupStaleConfigs(alive)

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

	// 第一遍：只做与配置无关的决定——离线校准、停用即停进程、退避跳过。
	// 这些都在改本地状态，必须留在串行路径上。
	var pending []TunnelVO
	for _, t := range tunnels {
		// 先校准「已注册」标记：本机还挂着「注册成功」的印象、而服务端已经
		// 报告离线时，以服务端为准（详见 calibrateRegistered 的说明）。
		a.calibrateRegistered(t.ID, t.Online)

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
		pending = append(pending, t)
	}

	// 从上一轮停下的位置开始环形遍历（见 syncStart）。
	//
	// 不这么做就会「尾部饿死」：清单按 id 倒序，配置并发 6 条、整轮 45 秒，
	// 前几条一旦持续卡到超时，后面的一直排不上队；下一轮又从同一条开始，
	// 于是尾部隧道永远拿不到配置——新建的隧道一直「连接中」，改了配置的
	// 隧道一直跑旧配置，而且重启客户端也没用（位次没变）。
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

	// 清单里带了每条隧道配置的摘要(config_rev):与本地缓存一致,就说明服务端
	// 此刻会生成的字节和我们已经落盘的那份**一模一样**,再发一次请求只是白等
	// 一个往返。
	//
	// 这是「每轮请求数随隧道数增长」的解法——变了才拉。摘要由服务端按渲染结果
	// 算出,隧道字段、分组限速、站点设置、客户端密钥任何一处变化都会让它变化,
	// 不存在「摘要没变、配置其实变了」。
	// 老服务端不下发摘要(空串),那些隧道照旧逐条拉取。
	type cachedCfg struct {
		t    TunnelVO
		text string
	}
	var (
		cached    []cachedCfg
		needFetch []TunnelVO
		// fetchPos 是 needFetch[i] 在 pending(本轮环形顺序)里的下标。
		// 续传位置必须按这个下标推进,不能按「派发数 + 命中数」——
		// 命中的隧道散落在清单各处,按总数推进会越过还没处理的那一段。
		fetchPos []int
	)
	for i, t := range pending {
		if text, ok := a.cachedConfig(t.ID, t.ConfigRev); ok {
			cached = append(cached, cachedCfg{t: t, text: text})
			continue
		}
		needFetch = append(needFetch, t)
		fetchPos = append(fetchPos, i)
	}
	// 刻意不为「跳过」写日志:每 20 秒一条会把真正有用的行挤出队列,
	// 而这件事本身没有任何需要用户知道的信息。

	// 第二遍起：并发取配置，每收到一条就立刻处理。
	//
	// 只并发「取配置」这一件事：写文件、起停进程、记退避、记失败都在改同一批
	// 共享状态，把它们并发化得把这套状态机重新设计一遍，风险远大于收益。
	// 而延迟的大头恰恰是网络往返——逐条串行时整轮耗时约为「隧道数 × 响应时间」，
	// 隧道一多就会明显拖长，界面上只剩一个「连接中」。
	//
	// 收到即处理，而不是等全部配置取完再统一启动：单次请求超时可达 15 秒，
	// 等齐的话最慢的那一条会把已经取到配置的隧道也挡住。所有状态变更
	// （写文件、起停、记失败）仍然只发生在主协程的这段循环里，
	// 并发只存在于网络请求。
	applyCfg := func(t TunnelVO, cfgText, servedRev string, cfgErr error) {
		if cfgErr != nil {
			// 单条隧道的配置拉不到，不该让整次同步中断——
			// 其他隧道仍然要对账，否则一条坏隧道会拖住全部。
			failSync(t, "拉取配置失败："+cfgErr.Error())
			return
		}
		if cfgText == "" {
			// 空配置必须当成失败，不能静默跳过。
			//
			// 跳过的话这一轮会被记成完全成功（SyncErr 清空、LastSyncAt 更新），
			// 而那条隧道什么都没连上，界面上也没有任何原因——
			// 用户只能看到一个「连接中」，等多久都不会变。
			failSync(t, "服务端未返回该隧道的配置")
			return
		}

		// 摘要一律以**产出这份正文的那次响应**为准(响应头 X-Config-Rev),
		// 而不是清单里那一份:两者是两次渲染,中间隔着一次网络往返,管理端
		// 在这期间改了隧道的话,「新正文 + 旧摘要」会被配成一对缓存下来,
		// 之后就可能长期跑着过时的配置。
		//
		// 老服务端没有这个头:那就干脆不记账(退回清单摘要会重新引入同样的
		// 不匹配),该隧道保持逐轮拉取。
		t.ConfigRev = servedRev

		prev := a.appliedConfigOf(t.ID)
		cfgChanged := cfgText != prev

		// 摘要必须始终描述 applied 里的那份文本(cachedConfig 靠这个等式)。
		//
		//   - 文本没变:把摘要对齐到本次响应。响应里没有摘要(老服务端)时
		//     是**删除**旧值,不是保留——留着的话下一轮会拿它去比清单,
		//     而它描述的文本可能早已不是磁盘上那份了;
		//   - 文本变了:旧摘要立刻作废,等 writeAndStart 成功后再按新文本记账;
		//     启动失败则保持「无摘要」,下一轮必然重新拉取。
		if !cfgChanged {
			a.setConfigRev(t.ID, t.ConfigRev)
		} else {
			a.setConfigRev(t.ID, "")
		}

		switch {
		case !a.mgr.Running(t.ID):
			if err := a.writeAndStart(t, cfgText); err != nil {
				failStart(t, "启动失败："+err.Error())
				return
			}
			// 退避已在 writeAndStart 里、启动之前清掉。这里**不能**再清一次：
			// 进程秒退时退出回调可能已经登记了新退避，这一下会把它抹掉。
			changed = true
		case cfgChanged:
			// 只重启这一条：其他隧道的连接不受影响。
			a.emitTunnelLog(t.Name, "配置有变化（"+diffHint(prev, cfgText)+"），正在重连")
			if err := a.mgr.Stop(t.ID); err != nil {
				// 停不下来属于环境级故障（进程管理器异常）：
				// 这一条做不了，下一轮同步还会再来。
				failStart(t, "重连失败：停止旧进程失败："+err.Error())
				return
			}
			if err := a.writeAndStart(t, cfgText); err != nil {
				failStart(t, "重连失败："+err.Error())
				return
			}
			changed = true
		}
	}

	results, dispatched := a.streamTunnelConfigs(ctx, base, apiKey, needFetch)
	for res := range results {
		applyCfg(res.tunnel, res.text, res.rev, res.err)
	}
	// 命中缓存的隧道同样要走一遍应用逻辑：进程可能没在跑、配置可能还没落盘。
	// 它们不产生网络请求，所以放在拉取之后处理——先完成要等网络的，
	// 不需要等网络的立刻跟上。
	// 摘要沿用清单里那一份:命中缓存的前提本就是「清单摘要与本地记账一致」,
	// 把同一个值写回去,记账的含义不变。
	for _, c := range cached {
		applyCfg(c.t, c.text, c.t.ConfigRev, nil)
	}
	// 记下续传位置：派发是从本轮起点开始、按顺序进行的，派发到哪儿就意味着
	// 这一轮走到哪儿。下一轮从那里接着来，被截止时间砍掉的尾部排到最前。
	// 全派发完时它会回到本次的起点（rot + 条数 ≡ rot），顺序保持不变。
	if n := len(pending); n > 0 {
		// 必须按**原清单里的位置**推进,不能按「派发数 + 命中缓存数」:
		// 缓存命中散布在清单各处(哪条没变就跳过哪条),按个数相加等于把游标
		// 推到更靠后的位置,中间那些还没轮到请求的隧道会被整段跳过;
		// 极端情况下游标会在两个位置之间来回,尾部几条永远进不了请求队列。
		next := rot
		if d := int(dispatched.Load()); d > 0 {
			if d > len(fetchPos) {
				d = len(fetchPos)
			}
			// fetchPos 是**环形左移之后**的下标,而 syncStart 是在原清单里
			// 的位置,所以要加回 rot —— 漏掉这一步游标会往回走。
			next = (rot + fetchPos[d-1] + 1) % n
		}
		a.syncStart = next
	}

	if ctx.Err() != nil {
		// 超时不算完全成功：SyncErr 要亮出来，否则用户以为同步过了，
		// 而部分隧道根本没对上账。已处理完的隧道不受影响，保持原状。
		roundErr := fmt.Errorf("本轮同步超时（超过 %s），未处理的隧道将在下一轮优先重试", syncRoundTimeout)
		if len(failures) > 0 {
			roundErr = fmt.Errorf("%w；另有 %d 条隧道同步失败", roundErr, len(failures))
		}
		return changed, roundErr
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

// fetchTunnelConfig 拉取某条隧道专属的配置文本。
//
// 只取这一条：配置文件里只有一条 [[proxies]]，进程之间不会互相干扰。
func (a *App) fetchTunnelConfig(ctx context.Context, base, apiKey string, id uint) (string, string, error) {
	endpoint := fmt.Sprintf("%s/api/user/client/config?tunnel_id=%d", base, id)
	text, rev, err := a.getRawWithRev(ctx, endpoint, apiKey)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(text), rev, nil
}

// cfgResult 是一条隧道的配置拉取结果。
type cfgResult struct {
	tunnel TunnelVO
	text   string
	// rev 是服务端**随这份正文**给出的摘要(响应头 X-Config-Rev)。
	// 老服务端为空,由调用方退回清单里的 config_rev。
	rev string
	err error
}

// streamTunnelConfigs 并发拉取一批隧道的配置，结果按**完成顺序**流出。
//
// 为什么值得单独做这一步：逐条串行时整轮同步的耗时约等于「隧道数 × 单次往返」，
// 十几条隧道就能让界面长时间停在「连接中」。而这一步只读网络、不碰本地状态，
// 是整条链路上唯一能安全并发的一段。
//
// 返回的是通道而不是汇总好的 map：调用方每收到一条就立刻处理（起进程、记失败），
// 不必等最慢的那一条。单次请求超时可达 15 秒，先汇总再处理的话，
// 已经取到配置的隧道会被它挡住整整一个超时周期。代价是处理顺序不再是
// 隧道清单顺序——日志与失败记录的先后取决于网络快慢，这是可接受的取舍。
//
// 出错也**不中断**：错误作为一条结果流出，由调用方逐条记录，
// 一条隧道拉取失败不会掩盖其他隧道的对账。
// 单次请求的超时由 a.http 自己的 Timeout 兜底；整轮还有 ctx 截止时间
// （调用方传入），到点后未派发的任务直接放弃，由下一轮同步补上。
// 通道在全部结果流出（或截止）后关闭，调用方 range 到结束即可。
//
// 第二个返回值是**实际派发出去的条数**：调用方据此推进续传位置
// （见 applySyncData 里的 syncStart）。不能用「收到的结果条数」代替——
// 截止时 worker 的 fetch 失败后可能直接返回、不再投递结果，那样算出来
// 的位置会原地不动，下一轮又从头开始处理同一批隧道。
func (a *App) streamTunnelConfigs(ctx context.Context, base, apiKey string, tunnels []TunnelVO) (<-chan cfgResult, *atomic.Int64) {
	dispatched := &atomic.Int64{}
	results := make(chan cfgResult, len(tunnels))
	if len(tunnels) == 0 {
		close(results)
		return results, dispatched
	}

	workers := configFetchConcurrency
	if workers > len(tunnels) {
		workers = len(tunnels)
	}

	jobs := make(chan TunnelVO)
	// 结果通道带足缓冲：worker 写完就能去领下一个任务，不会因为主协程
	// 还在处理上一条结果而空等。

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-jobs:
					if !ok {
						return
					}
					text, rev, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
					select {
					case results <- cfgResult{tunnel: t, text: text, rev: rev, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// 派发与收集分开：派发放在独立协程里，主协程专心收结果。
	// 若在这里同步派发，jobs 写满时就会和收结果互相卡死。
	// 派发同样受 ctx 约束：截止后不再派发剩余任务（close(jobs) 让
	// worker 正常退出，wg.Wait 才不会卡住，results 才能关闭）。
	go func() {
		defer close(jobs)
		for _, t := range tunnels {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
				dispatched.Add(1)
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	return results, dispatched
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
	// 清退避要放在**启动之前**，不能等启动成功之后再清。
	//
	// 进程退出回调是异步的：frpc 因为凭据失效之类的原因秒退时，回调可能
	// 在 Start 返回之后、我们清退避之前就把新退避登记好了——随后那次清理
	// 会把它抹掉，下一轮同步立刻又拉起进程，退避形同不存在。
	// 放在启动前，最坏情况也只是「刚失败过一次又立刻重试一次」。
	a.clearRetry(t.ID)
	// 重新拉起之前先清掉「已注册」：旧进程的注册已经作废，新的要等 frpc
	// 再报一次 start proxy success。不清的话重连期间界面会一直显示「运行中」。
	a.setTunnelRegistered(t.ID, false)

	// 把配置路径一起打出来：隧道起不来时，第一件要确认的就是
	// 「客户端到底用了哪份配置」，而这份配置是每条隧道一份的。
	a.emitTunnelLog(t.Name, "开始加载隧道配置："+path)
	if err := a.mgr.Start(t.ID, t.Name, path); err != nil {
		return err
	}
	// 记下「这次连接从什么时候开始」：frpc 进程活着但一直没注册成功时，
	// 界面要能显示已经等了多久，而不是永远一句「连接中」。
	a.markConnectStart(t.ID)

	// 记下这次写入的原文。下一次同步据此判断「配置有没有变」——
	// 不记的话每次同步都会判定为变化并重启一遍，连接会一直抖。
	// 服务端摘要(ConfigRev)一并记下:下一次同步据此判断「要不要重新拉」。
	// 只有配置**真的写进磁盘了**才记这笔账——失败路径上什么都不记,所以
	// 下一轮仍会重新拉取,而不是拿「服务端说没变」跳过一次没写成的配置。
	a.mu.Lock()
	a.applied[t.ID] = cfgText
	a.mu.Unlock()
	a.setConfigRev(t.ID, t.ConfigRev)
	return nil
}

// setConfigRev 更新某条隧道记录的配置摘要。
//
// 空摘要表示「服务端没给」——必须**删除**旧值，而不是留着不动：
// 留着的话，下一轮会拿这个旧摘要去比对清单，而它描述的文本可能已经不是
// 磁盘上那份了（老服务端期间配置被改过）。删掉之后 cachedConfig 一律不命中，
// 该隧道退回逐轮拉取：慢一点，但不会把旧配置当成新的。
func (a *App) setConfigRev(id uint, rev string) {
	a.mu.Lock()
	if rev == "" {
		delete(a.cfgRev, id)
	} else {
		a.cfgRev[id] = rev
	}
	a.mu.Unlock()
}

// startTunnelProcess 为用户主动点「连接」的隧道拉配置并启动。
//
// ctx 是这次开关操作的整笔预算（见 manualOpTimeout）：请求失败或超时都要
// 如实返回，界面据此提示，而不是让按钮一直转。
func (a *App) startTunnelProcess(ctx context.Context, t TunnelVO) error {
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
	// 手动点连接一律重新拉取,不受摘要缓存影响。
	//
	// 「用户刚刚在网页端改了配置、然后点连接」是最常见的操作顺序,而这中间
	// 客户端可能还没跑过一轮同步(清单里的 config_rev 还是旧的)。用摘要跳过
	// 就等于让用户拿到改之前的配置——他改了端口却连到旧端口,而且日志里
	// 没有任何异常。一次往返换一个「点了就是最新的」,这个代价值得。
	cfgText, servedRev, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
	if err != nil {
		return err
	}
	if cfgText == "" {
		return errors.New("服务端未返回该隧道的配置")
	}
	t.ConfigRev = servedRev
	return a.writeAndStart(t, cfgText)
}

// stopTunnelProcess 停掉某条隧道的进程。
func (a *App) stopTunnelProcess(t TunnelVO) error {
	a.emitTunnelLog(t.Name, "隧道已断开")
	// 主动停也要立刻清掉「已注册」：不等进程退出回调，界面马上就是「未连接」。
	a.setTunnelRegistered(t.ID, false)
	return a.mgr.Stop(t.ID)
}

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

// cleanupStaleConfigs 清掉「服务端已经没有」的隧道在本地留下的配置文件。
//
// # 为什么以磁盘为准，而不是只看「刚停掉的进程」
//
// 隧道可能在**网页端**被删除，或客户端删除请求在服务端完成之后遇到网络错误：
// 这时客户端这一侧既没有它的进程、也没有内存状态，上面那个「收进程」的循环
// 根本不会经过它，pruneTunnelState 又只清内存——磁盘上的 frpc.toml 就一直留着。
//
// 所以这里扫一遍隧道目录，凡是不在服务端清单里的都清掉。目录名是隧道 ID。
//
// 进程还没停下来的**刻意不删**：删了它仍在跑，而配置文件没了意味着下次排查时
// 什么都看不到；磁盘上的残留本身就是「待重试状态」，下一轮同步会再来一次。
func (a *App) cleanupStaleConfigs(alive map[uint]bool) {
	dir, err := frpcTunnelsDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// 目录不存在是正常的（还没建过隧道）。
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id64, perr := strconv.ParseUint(e.Name(), 10, 32)
		if perr != nil {
			// 不是隧道目录（用户自己放的东西），别动它。
			continue
		}
		id := uint(id64)
		if alive[id] {
			continue
		}
		if a.mgr.Running(id) {
			a.warnConfigCleanup(id, "本地 frpc 进程尚未停止，配置文件暂未清理")
			continue
		}
		if rerr := removeFrpcConfig(id); rerr != nil {
			a.warnConfigCleanup(id, "本地配置文件清理失败（其中含接入密钥）："+rerr.Error())
			continue
		}
		// 清理成功：把「已提示过」的标记一并撤掉。
		//
		// 不撤的话这张表只增不减——反复遇到「清理失败 → 后来成功」的不同隧道，
		// 每个 ID 都会永久占一个条目。
		a.clearCleanupWarn(id)
		log.Printf("[client] 已清理隧道 %d 的本地配置（该隧道在服务端已不存在）", id)
	}
}

// clearCleanupWarn 撤掉「已提示过清理失败」的标记。
func (a *App) clearCleanupWarn(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cleanupWarned, id)
}

// warnConfigCleanup 就「配置清理失败」提示用户，同一隧道只提示一次。
//
// 不重复提示是因为它会每 20 秒重试一次：每次都弹提示只会把界面刷满，
// 而结论一直是同一个。真正的重试仍在继续（残留文件还在，下轮会再试）。
func (a *App) warnConfigCleanup(id uint, msg string) {
	a.mu.Lock()
	if a.cleanupWarned == nil {
		a.cleanupWarned = map[uint]bool{}
	}
	first := !a.cleanupWarned[id]
	a.cleanupWarned[id] = true
	a.mu.Unlock()

	if first {
		log.Printf("[client] 隧道 %d：%s", id, msg)
		a.emitNotice(msg)
	}
}

// pruneTunnelState 丢弃「服务端已经没有」的隧道留下的各种记录。
//
// 不按运行中的进程来清，是因为一条隧道可能因为启动失败而没有进程：
// 之后它被服务端删掉，这些记录就再也没有机会被访问或清理。
//
// 每张按隧道记账的表都要清，包括 applied：它存的是「最近一次写入磁盘的配置原文」，
// 每条几百字节到几 KB。反复「建了、删掉」会让它一直占着内存，
// 而它的用途（判断配置有没有变）只对还存在的隧道有意义。
//
// cleanupWarned 同理：它记的是「这条隧道的清理失败已经提示过了」，
// 隧道都不存在了，这个标记没有任何意义。
func (a *App) pruneTunnelState(alive map[uint]bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id := range a.tunnelErrs {
		if !alive[id] {
			delete(a.tunnelErrs, id)
		}
	}
	for id := range a.retries {
		if !alive[id] {
			delete(a.retries, id)
		}
	}
	for id := range a.applied {
		if !alive[id] {
			delete(a.applied, id)
		}
	}
	// 摘要与配置原文是一对，必须同生共死：只清文本会留下一个孤儿摘要，
	// 它会让下一次同 id 的隧道（id 不会复用，但地图会一直长）永远命中不了。
	for id := range a.cfgRev {
		if !alive[id] {
			delete(a.cfgRev, id)
		}
	}
	for id := range a.cleanupWarned {
		if !alive[id] {
			delete(a.cleanupWarned, id)
		}
	}
	// 下面这几张表是后加的，同样要清：它们都是「按隧道 id 记账」的小结构，
	// 每项只有几十字节，但一条隧道被删掉之后就再没有人会读写它——
	// 反复「建了、报错、删掉」会让它们随进程寿命一直长下去，属于纯粹的泄漏。
	for id := range a.registered {
		if !alive[id] {
			delete(a.registered, id)
		}
	}
	for id := range a.registeredAt {
		if !alive[id] {
			delete(a.registeredAt, id)
		}
	}
	for id := range a.errEmitAt {
		if !alive[id] {
			delete(a.errEmitAt, id)
		}
	}
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

// cachedConfig 在服务端摘要与本地记账一致时返回缓存的配置原文。
//
// 摘要由服务端按**渲染结果**算出（见 service.FrpcConfigRev），所以
// 「摘要相同」就是「服务端此刻会生成的字节与本地这份完全相同」——
// 不依赖任何「哪些字段会影响配置」的推断。
//
// 摘要为空（老服务端）或与记账不符时返回 false，调用方照旧拉取。
func (a *App) cachedConfig(id uint, rev string) (string, bool) {
	if rev == "" {
		return "", false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.cfgRev[id] != rev {
		return "", false
	}
	text := a.applied[id]
	if text == "" {
		return "", false
	}
	return text, true
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
