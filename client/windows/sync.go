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

// syncInterval 是后台自动同步的间隔。
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

// syncWithData 与 syncLocked 相同，但接入流程已经拿到过一份 client/info
// 响应时，直接把它交给同步，省掉一次重复的网络往返。
func (a *App) syncWithData(data *clientInfoData) (changed bool, err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	return a.applySyncData(data)
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

	var data clientInfoData
	if err := a.getJSON(context.Background(), base+"/api/user/client/info", apiKey, &data); err != nil {
		return false, err
	}
	return a.applySyncData(&data)
}

// applySyncData 执行对账。data 是本轮要采纳的接入信息快照——
// 正常路径来自刚请求的 /client/info，接入路径来自 Connect 已验证
// Key 有效的同一次响应。
func (a *App) applySyncData(data *clientInfoData) (changed bool, err error) {
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
	applyCfg := func(t TunnelVO, cfgText string, cfgErr error) {
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

		prev := a.appliedConfigOf(t.ID)
		cfgChanged := cfgText != prev

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

	// 整轮配置拉取限时：手动操作最多等这么久，超时部分下一轮补齐。
	ctx, cancel := context.WithTimeout(context.Background(), syncRoundTimeout)
	defer cancel()
	for res := range a.streamTunnelConfigs(ctx, base, apiKey, pending) {
		applyCfg(res.tunnel, res.text, res.err)
	}

	if ctx.Err() != nil {
		// 超时不算完全成功：SyncErr 要亮出来，否则用户以为同步过了，
		// 而部分隧道根本没对上账。已处理完的隧道不受影响，保持原状。
		roundErr := fmt.Errorf("本轮同步超时（超过 %s），未处理的隧道将在下一轮自动重试", syncRoundTimeout)
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
func (a *App) fetchTunnelConfig(ctx context.Context, base, apiKey string, id uint) (string, error) {
	var text string
	endpoint := fmt.Sprintf("%s/api/user/client/config?tunnel_id=%d", base, id)
	if err := a.getRaw(ctx, endpoint, apiKey, &text); err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// cfgResult 是一条隧道的配置拉取结果。
type cfgResult struct {
	tunnel TunnelVO
	text   string
	err    error
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
func (a *App) streamTunnelConfigs(ctx context.Context, base, apiKey string, tunnels []TunnelVO) <-chan cfgResult {
	results := make(chan cfgResult, len(tunnels))
	if len(tunnels) == 0 {
		close(results)
		return results
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
					text, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
					select {
					case results <- cfgResult{tunnel: t, text: text, err: err}:
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
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
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
	cfgText, err := a.fetchTunnelConfig(context.Background(), base, apiKey, t.ID)
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
