package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// errSyncDeadline 表示这一轮同步的截止时间已经过了：该隧道既没有落盘配置，
// 也没有启动进程。
//
// 单独做成哨兵而不是直接返回 ctx.Err()：调用方必须把它和「拉取失败」
// 「启动失败」区分开——后两者要记进隧道行并推进退避，而它只是「这一轮
// 没轮到」，下一轮会照常重试。混在一起的话，用户会在「同步超时」的同时
// 看到一条并不存在的隧道失败原因，而隧道其实什么都没做错。
var errSyncDeadline = errors.New("本轮同步已超时，该隧道未写入配置也未启动")

// writeAndStart 落盘配置并启动该隧道的 frpc 进程。
//
// ctx 是本轮的整笔预算（整轮同步的截止时间，或一次手动开关操作的预算）。
// 已经过了截止时间就**什么都不做**：配置正文可能是超时之前取到、超时之后
// 才轮到处理的，照旧落盘并拉起进程，就会出现「界面报同步超时，进程却已经
// 起来了」——用户看到的错误与客户端的实际状态对不上，而下一轮同步又会
// 把这条已经起来的进程当成「已运行」跳过，两面都不一致。
//
// 已经在上一轮/本轮早期起来的进程不受影响，也不会为了超时去杀它：
// 那是有效工作，杀掉只会让已经连上的连接抖一下。
//
// 启动成功与否由回调里的日志体现（frpc 会打印自己的连接过程），
// 这里不做额外等待：frpc 从启动到真正建好代理要一两秒，
// 阻塞在界面上等它只会让「连接」这个动作显得很慢。
func (a *App) writeAndStart(ctx context.Context, t TunnelVO, cfgText string) error {
	// 这一步必须放在最前面：frpcConfigPath 会顺手建出隧道目录，
	// 超时之后连这个副作用都不该留下。
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}
	path, err := frpcConfigPath(t.ID)
	if err != nil {
		return err
	}
	if err := writeFrpcConfig(t.ID, cfgText); err != nil {
		return err
	}
	// 落盘之后、动任何运行态之前再核对一次：写文件本身也要花时间，
	// 这中间的取消同样不该演变成「超时报错 + 进程起来了」。
	//
	// 此时配置已经写到磁盘上，但 applied/cfgRev 都还没记（和启动失败路径
	// 一样），所以下一轮仍会重新拉取、重新落盘——不会把一份没启动的配置
	// 当成「已应用」而跳过。
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}

	// 把配置路径一起打出来：隧道起不来时，第一件要确认的就是
	// 「客户端到底用了哪份配置」，而这份配置是每条隧道一份的。
	//
	// 这行日志刻意排在**最后一道闸之前**：它要走日志队列、还要往前端发事件，
	// 放在闸门与 Start 之间等于把那个窗口重新拉开（缺陷 3 说的就是这件事）。
	// 代价是极少数情况下会先打出这一行、紧接着因最后一道闸失败而报同步超时
	// ——这句话说的是「配置已经准备好」，并没有骗人。
	a.emitTunnelLog(t.Name, "开始加载隧道配置："+path)

	// 最后一道闸，紧贴启动动作。
	//
	// 前面两道闸之后还有写盘、清退避、清「已注册」、登记连接起点与启动代次
	// 这些动作，任何一步都可能把最后一点预算耗掉；而截止时间一旦在这之后
	// 才被发现，进程就已经起来了，用户看到的仍是「本轮同步超时 + 隧道连上了」
	// 这对互相矛盾的状态。
	//
	// 顺序上刻意让这道闸排在两次登记**之前**，而不是按字面「登记之后再查一次」：
	// 闸门拦下时若已经登记过连接起点或启动代次，就会留下脏状态——界面上挂着
	// 一段并不存在的等待，退出回调也会把这次没发生的启动当成真启动的产物。
	// 这两条登记又都必须早于 Start（frpc 可能在 Start 返回之前就打印注册成功，
	// 见 markConnectStart 的说明），所以「先查、再登记、立刻 Start」是唯一
	// 既不留脏状态、又不放宽窗口的排法。
	//
	// 登记之后不再设第四道闸：那两次登记只是两次 map 写入，窗口窄到可以忽略；
	// 而在它们之后再拦一道，反而要求「撤销代次登记」——那正是 state.go 里
	// 说明不能做的事（会抹掉下一次启动的记录）。
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return errSyncDeadline
		}
	}

	// 清退避要放在**启动之前**，不能等启动成功之后再清。
	//
	// 进程退出回调是异步的：frpc 因为凭据失效之类的原因秒退时，回调可能
	// 在 Start 返回之后、我们清退避之前就把新退避登记好了——随后那次清理
	// 会把它抹掉，下一轮同步立刻又拉起进程，退避形同不存在。
	// 放在启动前，最坏情况也只是「刚失败过一次又立刻重试一次」。
	//
	// 它排在最后一道闸之后：截止时间已过时不该再动退避——清掉它等于把
	// 「刚失败过、正在退避」的隧道提前放行，而这一轮根本没有尝试启动。
	a.clearRetry(t.ID)
	// 重新拉起之前先清掉「已注册」：旧进程的注册已经作废，新的要等 frpc
	// 再报一次 start proxy success。不清的话重连期间界面会一直显示「运行中」。
	a.setTunnelRegistered(t.ID, false)

	// 起点必须在**启动之前**记下：frpc 可能在 Start 返回之前就打印
	// start proxy success，注册回调会清掉起点；若在 Start 之后再写，
	// 等于把一次已经结束的等待又贴回来，之后掉线重连显示的时长里
	// 会混进那段早就连上的时间。
	a.markConnectStart(t.ID)
	// 记账必须在 Start **之前**：见 markStartGeneration 的说明——记的是
	// 「启动那一刻的账号」，中间插一次退出登录也不会记错。
	a.markStartGeneration(t.ID)
	if err := a.mgr.Start(t.ID, t.Name, path); err != nil {
		// 没起来就不算「连接中」：留着起点会让界面显示一段并不存在的等待。
		a.clearConnectStart(t.ID)
		return err
	}

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
	err = a.writeAndStart(ctx, t, cfgText)
	if errors.Is(err, errSyncDeadline) {
		// 手动点连接时「没预算了」就是这次操作超时，不是这条隧道的启动问题：
		// 换成 ctx 的错误，交给 describeManualErr 翻成「操作超时，请重试」。
		// 直接把哨兵的说明抛出去，用户会看到一句与本机状态无关的同步术语。
		return ctx.Err()
	}
	return err
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

func writeFrpcConfig(tunnelID uint, text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("服务端返回的配置为空")
	}
	path, err := frpcConfigPath(tunnelID)
	if err != nil {
		return err
	}
	// 原子写入：配置被写坏时 frpc 直接起不来，而在此之前它可能一直连得上。
	if err := writeFileAtomic(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("写入客户端配置失败: %w", err)
	}
	return nil
}
