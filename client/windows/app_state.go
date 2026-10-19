package main

// 本文件是「状态快照」这一职责：把 App 里散落的字段组装成前端要的 State。
//
// # 为什么单独成文
//
// app.go 原本同时承担四件事：构造、Wails 生命周期、同步门闩、状态快照。
// 其中状态快照被**高频**调用（每次 emitState、每次 GetState、日志回调），
// 而它的正确性依赖几条很容易被踩坏的隐性约定：
//
//   - 必须在持有 a.mu 的前提下组装（字段由它保护）；
//   - 日志代次**不能**在持锁后读（mu → logMu 会与日志路径形成锁环）；
//   - 快照不能推进 stateSeq（否则每次刷新都会让在途的合法事件被判旧）。
//
// 这些约定混在几百行的构造/生命周期代码里时，改一处很难看出会破坏哪一条。
// 单独成文之后，「读快照的地方只有这里」变得一目了然，上面三条也就有了
// 明确的落点。
//
// 与之配套的「推状态」在 state.go（emitState / snapshotForEmit），那边负责
// 取号与代次，两者共用 getStateLocked 以保证快照与序号同源。

import "time"

// maskKey 生成用于界面展示的脱敏形式，避免完整 Key 长时间暴露在屏幕上。
func maskKey(k string) string {
	if len(k) <= 12 {
		return "****"
	}
	return k[:12] + "********"
}

// GetState 返回当前完整状态。
func (a *App) GetState() State {
	// 日志代次必须在拿 a.mu 之前读：它由 logMu 保护，而 ClearLogs 是
	// 「先拿 logMu、再……不拿 a.mu」的顺序，这里若反过来（持 mu 读
	// logMu）就构成了 mu → logMu 的锁序，与日志路径形成环。
	//
	// 单独提前读一次的代价是它可能与下面那份快照差一拍（正赶上一次清空）。
	// 这可以接受：代次只用于「丢弃跨代次的旧批次」，而清空本身会立刻
	// 再推一次状态，界面下一次拿到的就是新值。
	logEpoch := a.currentLogEpoch()

	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getStateLocked(logEpoch)
}

// getStateLocked 在**已持有 a.mu**（读锁或写锁）的前提下组装状态快照。
//
// 拆出来的唯一目的是给 emitState 用：那里必须把「取快照」与「取序号/代次」
// 放在同一次持锁里（见 snapshotForEmit），否则会出现「旧代次的快照配新序号」
// 这种前端无法识别为旧事件的组合。
//
// logEpoch 由调用方传入：它在 logMu 保护下，不能在本函数里读（会形成
// mu → logMu 的反向锁序，见 GetState 的说明）。
func (a *App) getStateLocked(logEpoch uint64) State {
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
	// 一次取运行集合：逐条 Running 会在隧道很多时放大成 O(N) 次加锁，
	// 而状态快照会被每次状态事件（含高频日志）调用。
	running := a.mgr.RunningSet()
	for i := range tunnels {
		_, isRunning := running[tunnels[i].ID]
		tunnels[i].Running = isRunning
		tunnels[i].Registered = a.registered[tunnels[i].ID]
		// 进程在跑但还没注册成功：把已等待时长带出去，界面据此显示
		// 「连接中 · 42 秒」，而不是一句没有信息量的「连接中」。
		//
		// 直接读 a.connectAt 而不是调 connectWaited：这里已经持有读锁，
		// 再取一次读锁在有写者在排队时会卡住（Go 的 RWMutex 不保证重入）。
		if tunnels[i].Running && !tunnels[i].Registered {
			if at, ok := a.connectAt[tunnels[i].ID]; ok {
				tunnels[i].PendingSeconds = int(time.Since(at).Seconds())
			}
		}
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
		// 清理失败独立于同步错误：同步成功不代表含密钥的残留文件已经清掉，
		// 而界面只有一个 SyncErr 位置可显示。两处都有时优先显示同步错误
		// （它更可能是用户当下要处理的），清理状态在下一轮仍会出现。
		SyncErr:        firstNonEmpty(a.syncErr, a.cleanupErr),
		LastSyncAt:     lastSync,
		ConfigError:    a.cfgErr,
		Version:        Version(),
		LogEpoch:       logEpoch,
		// 快照也带上当前序号：前端拿它和事件里的序号比较，判断「这份快照
		// 比我已经见过的状态新还是旧」。
		//
		// 这里读的是**当前**值而不是递增后的值——快照不是一次推送，不该
		// 消耗序号（否则每次 GetState 都会让在途的合法事件被判旧）。
		// emitState 会在这个值的基础上再取一个新号（见 snapshotForEmit）。
		StateSeq: a.stateSeq,
		// 账号代次与状态同源：前端拿它区分「旧账号的迟到事件」与「新账号
		// 的事件」（见 State.AuthGen）。这里已持有读锁，直接读即可。
		AuthGen: a.authGeneration,
		// Running 是「有没有任意一条隧道在连」，界面的状态点用它。
		// 直接用上面那份集合，避免再取一次管理器锁。
		Running:   len(running) > 0,
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
