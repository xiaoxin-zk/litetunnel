package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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
		// 只用于「整轮颗粒无收」时的兜底轮转（见 sync_cursor.go 的
		// nextStart）：必须按这个下标而不是按条数，否则环形左移之后
		// 算出的位置会往回走。
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
	//
	// 返回值 settled 决定游标能不能越过这条隧道（见 sync_cursor.go）：
	// 只有走到明确结论的才算落定，因截止时间提前返回的不算。
	applyCfg := func(t TunnelVO, cfgText, servedRev string, cfgErr error) (settled bool) {
		// 截止时间已经过了：这一条完全不碰。
		//
		// 必须放在最前面，包括「取到配置之后」这条路径：配置正文是在截止
		// 之前就取到的，处理它时可能已经超时。若照旧落盘并拉起进程，用户
		// 会同时看到「本轮同步超时」和一条实际已经连上的隧道——两端说法
		// 互相矛盾；更糟的是下一轮同步会把这条已在跑的进程当成「已运行」
		// 跳过，错误提示会一直挂着，却再没有人去纠正它。
		//
		// 之所以不杀本轮早期已经起来的进程：那是截止之前完成的有效工作，
		// 为了一个时间点去杀它只会让已经连上的连接抖一下。
		//
		// 这一条**不落定**：它没做错任何事，只是没轮到。游标必须停在它这里，
		// 让下一轮优先重试它（见 sync_cursor.go 的 nextStart）。
		if ctx.Err() != nil {
			return false
		}
		if cfgErr != nil {
			// 单条隧道的配置拉不到，不该让整次同步中断——
			// 其他隧道仍然要对账，否则一条坏隧道会拖住全部。
			failSync(t, "拉取配置失败："+cfgErr.Error())
			return true
		}
		if cfgText == "" {
			// 空配置必须当成失败，不能静默跳过。
			//
			// 跳过的话这一轮会被记成完全成功（SyncErr 清空、LastSyncAt 更新），
			// 而那条隧道什么都没连上，界面上也没有任何原因——
			// 用户只能看到一个「连接中」，等多久都不会变。
			failSync(t, "服务端未返回该隧道的配置")
			return true
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
			if err := a.writeAndStart(ctx, t, cfgText); err != nil {
				// 截止时间是 writeAndStart 里最后一道闸：它可能是刚过期的
				// （上面那次检查之后又走了一段）。这里同样不能记成启动失败
				// ——隧道什么都没做错，下一轮会优先重试。
				//
				// 不落定：游标停在这里，下一轮从它开始（见 sync_cursor.go）。
				if errors.Is(err, errSyncDeadline) {
					return false
				}
				failStart(t, "启动失败："+err.Error())
				return true
			}
			// 退避已在 writeAndStart 里、启动之前清掉。这里**不能**再清一次：
			// 进程秒退时退出回调可能已经登记了新退避，这一下会把它抹掉。
			changed = true
		case cfgChanged:
			// 停旧进程之前再确认一次预算：停了却因超时不再拉起，
			// 等于把一条本来能用的连接停在那里——比什么都不做更糟。
			if ctx.Err() != nil {
				return false
			}
			// 只重启这一条：其他隧道的连接不受影响。
			a.emitTunnelLog(t.Name, "配置有变化（"+diffHint(prev, cfgText)+"），正在重连")
			if err := a.mgr.Stop(t.ID); err != nil {
				// 停不下来属于环境级故障（进程管理器异常）：
				// 这一条做不了，下一轮同步还会再来。
				failStart(t, "重连失败：停止旧进程失败："+err.Error())
				return true
			}
			if err := a.writeAndStart(ctx, t, cfgText); err != nil {
				if errors.Is(err, errSyncDeadline) {
					return false
				}
				failStart(t, "重连失败："+err.Error())
				return true
			}
			changed = true
		}
		// 走到这里说明这条隧道有了明确结论（成功应用，或本来就不用动）。
		return true
	}

	// 本轮进度账：谁落定了、派发到哪儿（见 sync_cursor.go）。
	round := newSyncRound(pending, fetchPos)

	results, dispatched := a.streamTunnelConfigs(ctx, base, apiKey, needFetch)
	for res := range results {
		if applyCfg(res.tunnel, res.text, res.rev, res.err) {
			round.settle(res.tunnel.ID)
		}
	}
	// 命中缓存的隧道同样要走一遍应用逻辑：进程可能没在跑、配置可能还没落盘。
	// 它们不产生网络请求，所以放在拉取之后处理——先完成要等网络的，
	// 不需要等网络的立刻跟上。
	// 摘要沿用清单里那一份:命中缓存的前提本就是「清单摘要与本地记账一致」,
	// 把同一个值写回去,记账的含义不变。
	for _, c := range cached {
		if applyCfg(c.t, c.text, c.t.ConfigRev, nil) {
			round.settle(c.t.ID)
		}
	}
	// 记下续传位置：只按**落定**推进，本轮没轮到的隧道下一轮优先。
	// 旧实现按「派发数」推进，把截止时间之后没应用的隧道也算成已处理，
	// 于是游标越过它们（详见 sync_cursor.go 开头的说明）。
	if n := len(pending); n > 0 {
		// 派发在独立协程里进行，必须等结果通道关闭（此时 worker 与派发协程
		// 都已退出）再读计数，否则读到的是中间值。
		round.setDispatched(int(dispatched.Load()))
		a.syncStart = round.nextStart(rot, n)
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
