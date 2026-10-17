package main

import (
	"fmt"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

func shortLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// emitLog 往运行日志里追加一行客户端自身的说明（不带隧道前缀）。
//
// 与 emitTunnelLog 分开：带前缀的行是「某条隧道发生了什么」，
// 不带前缀的行是「客户端整体在做什么」（启动同步、用时统计）。
// 混在一起会让用户以为启动统计也属于某条隧道。
func (a *App) emitLog(msg string) {
	a.appendLogLine(time.Now().Format("15:04:05") + "  " + msg)
}

// emitTunnelLog 往运行日志里追加一行带隧道前缀的说明。
//
// 前缀格式与 frpc 子进程的输出一致（Tunnel/<名字>），
// 这样「客户端说的话」和「frpc 说的话」在日志里能按隧道对齐——
// 每条隧道一个进程之后，日志是多个进程交织在一起的，
// 没有前缀就分不出哪一行属于哪条隧道。
func (a *App) emitTunnelLog(name, msg string) {
	a.appendLogLine(fmt.Sprintf("%s  Tunnel/%s  %s", time.Now().Format("15:04:05"), name, msg))
}

// maxLogBatch 是一批日志的上限。
//
// 有上限是为了控制单次事件的大小：一次推几千行会让前端在一次事件处理里
// 做几千次数组操作，首屏也要等更久才看到第一行。
//
// 它同时是**每次 flush 的取出上限**（不只是触发阈值）：只拿它当阈值、
// flush 时一次取走整个队列的话，积压越久单次事件就越大，正好把这里的
// 上限意义抵消掉。
const maxLogBatch = 200

// maxLogQueue 是待推送队列的容量上限。
//
// 必须有上限：生产速度超过推送速度时（前端消费慢、frpc 持续刷日志），
// 队列会无界增长，而这段内存恰好在「日志最多」的时候涨得最快——那正是
// 出故障、最需要客户端还能响应的时刻。
//
// 取 2000：按每 120ms 推 200 行算，约 1.2 秒的缓冲，足够吸收正常抖动；
// 再大就只是拿内存换更旧的日志。
const maxLogQueue = 2000

// maxLogQueueBytes 是待推送队列的总字节上限。
//
// 只限行数挡不住「每行都很长」：单行在 frpc 那边可以留到 1 MiB，2000 行
// 就是 2 GiB。两份预算都设，谁先到按谁裁。
const maxLogQueueBytes = 1024 * 1024

// maxLogBatchBytes 是单次推送事件的总字节上限。
//
// 与 maxLogBatch 的关系同理：200 行 × 1 MiB 的事件要序列化、跨进程传、
// 再在 JS 里处理，会把 Wails 那条桥堵住很久——而桥一堵，后面所有事件
// （包括界面刷新）都排在它后面。
const maxLogBatchBytes = 128 * 1024

// logFlushInterval 是日志批量推送的间隔。
//
// 取 120ms：略大于人眼能分辨的停顿，日志看起来仍是实时滚动的；而事件数
// 上限变为约 8 次/秒，无论瞬间涌进多少行。frpc 连接失败时会在一瞬间刷出
// 上千行错误，逐行推送意味着上千次跨进程调用——前端那边的 200ms 合并渲染
// 只减少了 DOM 更新，挡不住这层开销，真正被堵住的是这条桥。
const logFlushInterval = 120 * time.Millisecond

// appendLogLine 把一行日志放进待推送队列。
//
// 所有往日志区写字的路径都必须走它（frpc 输出、客户端自己的说明），
// 否则同一段时间里的日志会出现两种先后顺序。
func (a *App) appendLogLine(line string) {
	if a.ctx == nil {
		return
	}
	// 攒满一批就立刻推，不等下一个时间片：一味等间隔会让日志洪峰时的
	// 延迟随着挤压行数一起增长（队列越长，轮到它越晚）。
	if a.pushLog(line) {
		select {
		case a.logKick <- struct{}{}:
		default:
			// 推送协程还没处理完上一次通知：它醒来时会取走一批。
		}
	}
}

// pushLog 入队一行，返回是否已经攒够一批可以立刻推送。
//
// 没有 ctx 依赖也不发事件：队列行为本身要能被单测覆盖——「有界」「丢最旧」
// 「一批不超过 maxLogBatch」这几条一旦坏了，症状只是日志少了几行或内存涨了，
// 不看队列本身根本发现不了。
func (a *App) pushLog(line string) bool {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	// 队列满了丢掉**最旧**的一批：日志是有时效的，留下最近的才能解释
	// 「刚才发生了什么」；丢最新的会让用户盯着一段早已过去的开头，
	// 而真正触发问题的那些行反而没了。
	//
	// 行数与总字节两份预算，谁先到按谁裁：单行可以很长，只数行数的话
	// 「2000 行 × 1 MiB」照样能把内存吃光。
	//
	// 一次丢一批（1/4）而不是逐条丢：逐条丢意味着每来一行都要把剩下的元素
	// 整体前移，在日志洪峰时这本身就成了新瓶颈——恰恰是这里要避免的事。
	if len(a.logBuf) >= maxLogQueue || a.logBufBytes >= maxLogQueueBytes {
		drop := len(a.logBuf) / 4
		if drop < 1 {
			drop = 1
		}
		for i := 0; i < drop && i < len(a.logBuf); i++ {
			a.logBufBytes -= len(a.logBuf[i])
		}
		a.logBuf = append(a.logBuf[:0], a.logBuf[drop:]...)
		a.logDropped += drop
	}

	a.logBuf = append(a.logBuf, line)
	a.logBufBytes += len(line)
	return len(a.logBuf) >= maxLogBatch
}

// takeLogBatch 取出一批待推送的日志行；没有内容时返回 nil。
//
// 一次最多取 maxLogBatch 行，剩下的留给下一轮：单次事件的尺寸因此有上界，
// 与积压了多久无关。
func (a *App) takeLogBatch() []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	if len(a.logBuf) == 0 && a.logDropped == 0 {
		return nil
	}

	n := len(a.logBuf)
	if n > maxLogBatch {
		n = maxLogBatch
	}

	// 再按总字节收一次：行数上限挡不住「每行都很长」，而一次事件过大
	// 会把 Wails 那条桥堵住——桥一堵，后面所有事件都跟着排队。
	//
	// 第一行无条件取（判断条件带 limit > 0）：单行本身就超预算时也得发出去，
	// 否则这一行永远清不出队列，后面的日志全部堵在它后面。
	// n == 0 是「只剩一条丢弃提示」的情况，此处不会取行。
	bytes := 0
	limit := 0
	for limit < n {
		size := len(a.logBuf[limit])
		if limit > 0 && bytes+size > maxLogBatchBytes {
			break
		}
		bytes += size
		limit++
	}
	n = limit

	// 丢弃提示单独占一行插在最前面：静默丢日志比丢日志本身更糟——
	// 用户会以为自己看到了完整的现场。
	batch := make([]string, 0, n+1)
	if a.logDropped > 0 {
		batch = append(batch, fmt.Sprintf("%s  [客户端] 日志积压，已丢弃 %d 行较早的记录",
			time.Now().Format("15:04:05"), a.logDropped))
		a.logDropped = 0
	}
	batch = append(batch, a.logBuf[:n]...)

	// 从头部截断而不是重新分配：剩下的是「更新的那部分」，顺序不变。
	for i := 0; i < n; i++ {
		a.logBufBytes -= len(a.logBuf[i])
	}
	a.logBuf = a.logBuf[n:]
	return batch
}

// flushLogs 把队列里攒下的日志行成批推给前端。
func (a *App) flushLogs() {
	if a.ctx == nil {
		return
	}
	batch := a.takeLogBatch()
	if len(batch) == 0 {
		return
	}
	wailsruntime.EventsEmit(a.ctx, "logs", batch)
}

// startLogFlusher 启动批量推送协程，进程生命周期内常驻。
//
// logKick 为 nil 时这里仍要能工作：nil 通道在 select 里永远不就绪，
// 于是退化成纯定时推送——不能因为少初始化一个 channel 就让日志彻底不显示。
func (a *App) startLogFlusher() {
	go func() {
		ticker := time.NewTicker(logFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-a.logKick:
			}
			a.flushLogs()
		}
	}()
}

// GetLogs 返回日志快照。
func (a *App) GetLogs() []string {
	return a.mgr.Logs()
}

// ClearLogs 清空日志缓冲。
func (a *App) ClearLogs() {
	a.mgr.ClearLogs()
}
