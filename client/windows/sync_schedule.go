package main

import (
	"context"
	"errors"
	"time"
)

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
	// 调度器是否该停，以根上下文（syncRoot）为准而不是 Wails 传入的 domReady
	// context：退出流程取消的是 syncRoot，而窗口 context 未必会及时取消，绑定
	// 它的话调度器可能继续空转唤醒、制造无效调度与状态事件。两者都监听，
	// 任一取消即停。
	root := a.rootContext()
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
			case <-root.Done():
				return
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
	// 先记下这一轮所属的账号代次。syncLocked 内部会释放同步锁，之后写
	// SyncErr / 推状态都发生在锁外：这期间可能已完成一次退出登录（代次
	// 前进）。旧任务若照常发布结果，会把上一个账号的同步错误写进新账号。
	gen := a.currentAuthGen()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()
	if apiKey == "" {
		// 尚未接入，没有可同步的东西。
		return
	}

	changed, err := a.syncLocked()
	if err != nil {
		if a.authGenCurrent(gen) {
			a.setSyncErr(err)
			a.emitState()
		}
		return
	}

	if !a.authGenCurrent(gen) {
		// 同步期间账号已切换：这一轮的结果属于旧账号，整段丢弃。
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
	// 后台同步自身也要可取消：退出时 syncRoot 被取消，这里立刻返回，
	// 关闭流程才等得到门闩——否则它要等这一整轮（最长 45 秒）跑完。
	if err := a.lockSync(a.rootContext()); err != nil {
		return false, err
	}
	defer a.unlockSync()
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
	ctx, cancel := a.newSyncContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return false, err
	}
	defer a.unlockSync()
	return a.syncWithDataLocked(ctx, data, seq)
}

// syncWithDataLocked 用调用方给的预算完成对账。
//
// ctx 必须是**整笔**操作的预算：接入流程拿它同时覆盖「校验 API Key」
// 与「随后对账」。各起一轮的话，最坏情况就是两轮 45 秒串在一起——
// 而用户只是点了一下「连接」。
func (a *App) syncWithDataLocked(ctx context.Context, data *clientInfoData, seq uint64) (changed bool, err error) {
	if seq <= a.appliedSyncSeq {
		return a.applySyncCtx(ctx)
	}
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
	return a.applySyncCtx(a.rootContext())
}

// applySyncCtx 与 applySync 相同，但把整轮同步挂到调用方给的预算上。
//
// 建/删/兑换这类操作要「改完立刻同步一次」，若同步各自再起一轮 45 秒的
// 预算，用户看到的总等待就是「请求 + 45 秒」。传入手动操作的整笔预算后，
// 同步只花它剩下的那部分时间。
func (a *App) applySyncCtx(parent context.Context) (changed bool, err error) {
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
	// 父上下文随应用退出而取消（见 rootContext）。
	ctx, cancel := context.WithTimeout(parent, syncRoundTimeout)
	defer cancel()

	data, err := a.fetchClientInfo(ctx, base, apiKey)
	if err != nil {
		return false, err
	}
	// 本轮在 syncMu 内拉取，序号必然最新（见 nextSyncSeq 的说明）。
	return a.applySyncData(ctx, data, a.nextSyncSeq())
}
