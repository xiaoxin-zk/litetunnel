package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// shortLine 截断一行文本用于日志展示。
//
// 必须按字符边界切：直接 s[:64] 会切在 UTF-8 中间，中文一行 22 个字就到
// 64 字节，「隧道名 + 中文说明」经常正好落在切口上，显示成半个乱码（�）。
func shortLine(s string) string {
	s = strings.TrimSpace(s)
	const max = 64
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// emitLog 往运行日志里追加一行客户端自身的说明（不带隧道前缀）。
//
// 走 Manager 的统一缓冲而不是只进推送队列：历史快照与实时推送必须是同一份
// 数据，否则界面重新加载日志时，启动同步、重连这类说明会凭空消失。
func (a *App) emitLog(msg string) {
	if a.mgr == nil {
		return
	}
	a.mgr.AppendRaw(time.Now().Format("15:04:05") + "  " + msg)
}

// emitTunnelLog 往运行日志里追加一行带隧道前缀的说明。
//
// 前缀格式与 frpc 子进程的输出一致（Tunnel/<名字>），
// 这样「客户端说的话」和「frpc 说的话」在日志里能按隧道对齐——
// 每条隧道一个进程之后，日志是多个进程交织在一起的，
// 没有前缀就分不出哪一行属于哪条隧道。
func (a *App) emitTunnelLog(name, msg string) {
	if a.mgr == nil {
		return
	}
	a.mgr.AppendRaw(fmt.Sprintf("%s  Tunnel/%s  %s", time.Now().Format("15:04:05"), name, msg))
}

// pendingLog 是一条等待推送的日志。
//
// 带序号是为了让「清空」能挡住清空前产生、清空后才入队的在途行。
type pendingLog struct {
	seq  uint64
	text string
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
func (a *App) appendLogLine(seq uint64, line string) {
	if a.ctx == nil {
		return
	}
	// 攒满一批就立刻推，不等下一个时间片：一味等间隔会让日志洪峰时的
	// 延迟随着挤压行数一起增长（队列越长，轮到它越晚）。
	if a.pushLog(seq, line) {
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
func (a *App) pushLog(seq uint64, line string) bool {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	// 清空前产生的行即使晚到也不再入队：它们属于用户已经清掉的那段历史。
	if seq != 0 && seq <= a.logDroppedSeq {
		return false
	}

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
			a.logBufBytes -= len(a.logBuf[i].text)
		}
		a.logBuf = append(a.logBuf[:0], a.logBuf[drop:]...)
		a.logDropped += drop
	}

	a.logBuf = append(a.logBuf, pendingLog{seq: seq, text: line})
	a.logBufBytes += len(line)
	return len(a.logBuf) >= maxLogBatch
}

// takeLogBatch 取出一批待推送的日志行；没有内容时返回 nil。
//
// 一次最多取 maxLogBatch 行，剩下的留给下一轮：单次事件的尺寸因此有上界，
// 与积压了多久无关。
func (a *App) takeLogBatch() []string {
	items, _ := a.takeLogBatchWithEpoch()
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.text
	}
	return out
}

// takeLogBatchWithEpoch 取出批次，并在**同一把锁内**捕获当时的代次。
//
// 分两步（先取批次、再读代次）会有一个窄窗口：清空恰好发生在两步之间时，
// 清空前的批次会被标成新代次，前端就过滤不掉了。
func (a *App) takeLogBatchWithEpoch() ([]pendingLog, uint64) {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	if len(a.logBuf) == 0 && a.logDropped == 0 {
		return nil, a.logEpoch
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
		size := len(a.logBuf[limit].text)
		if limit > 0 && bytes+size > maxLogBatchBytes {
			break
		}
		bytes += size
		limit++
	}
	n = limit

	// 丢弃提示单独占一行插在最前面：静默丢日志比丢日志本身更糟——
	// 用户会以为自己看到了完整的现场。它没有序号（seq=0），前端总是显示。
	batch := make([]pendingLog, 0, n+1)
	if a.logDropped > 0 {
		batch = append(batch, pendingLog{text: fmt.Sprintf("%s  [客户端] 日志积压，已丢弃 %d 行较早的记录",
			time.Now().Format("15:04:05"), a.logDropped)})
		a.logDropped = 0
	}
	for i := 0; i < n; i++ {
		batch = append(batch, a.logBuf[i])
		a.logBufBytes -= len(a.logBuf[i].text)
	}

	// 从头部截断而不是重新分配：剩下的是「更新的那部分」，顺序不变。
	a.logBuf = a.logBuf[n:]
	return batch, a.logEpoch
}

// logBatchEvent 是推送给前端的日志批次。
//
// epoch 用来丢弃「清空之前发出、清空之后才到」的旧批次；
// seqs 用来让前端按序号去重——快照与实时事件可能包含同一行。
type logBatchEvent struct {
	Epoch uint64   `json:"epoch"`
	Seqs  []uint64 `json:"seqs"`
	Lines []string `json:"lines"`
}

// flushLogs 把队列里攒下的日志行成批推给前端。
func (a *App) flushLogs() {
	if a.ctx == nil {
		return
	}
	batch, epoch := a.takeLogBatchWithEpoch()
	if len(batch) == 0 {
		return
	}
	ev := logBatchEvent{Epoch: epoch, Seqs: make([]uint64, len(batch)), Lines: make([]string, len(batch))}
	for i, item := range batch {
		ev.Seqs[i] = item.seq
		ev.Lines[i] = item.text
	}
	wailsruntime.EventsEmit(a.ctx, "logs", ev)
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

// LogSnapshot 是日志快照，连同它所属的代次与每行序号一起返回。
//
// 序号是去重的依据：前端加载快照时，可能有同一批日志正通过事件到达，
// 只比代次会把它们重复追加一次。
type LogSnapshot struct {
	Epoch uint64   `json:"epoch"`
	Seqs  []uint64 `json:"seqs"`
	Lines []string `json:"lines"`
}

// GetLogs 返回日志快照。
//
// 快照来自 Manager 的统一缓冲，因此 frpc 输出与客户端自身说明都在里面，
// 顺序也与实时推送一致（两者由同一把锁串行化）。
//
// 代次与快照在同一把锁内读取：分开读会让「清空」插在中间，
// 返回一份代次与内容对不上的快照。
func (a *App) GetLogs() LogSnapshot {
	a.logMu.Lock()
	defer a.logMu.Unlock()

	snap := LogSnapshot{Epoch: a.logEpoch}
	if a.mgr == nil {
		return snap
	}
	entries := a.mgr.LogEntries()
	snap.Seqs = make([]uint64, len(entries))
	snap.Lines = make([]string, len(entries))
	for i, e := range entries {
		snap.Seqs[i] = e.Seq
		snap.Lines[i] = e.Text
	}
	return snap
}

// LogCleared 是清空操作的结果。
type LogCleared struct {
	Epoch uint64 `json:"epoch"`
}

// ClearLogs 清空日志缓冲。
//
// 三处状态必须一起清：Manager 的历史、待推送队列、以及代次。
// 只清历史的话，队列里已经攒下的行会在下一次 flush 时照常出现，
// 用户看到的就是「点了清空，日志又自己冒回来」。
func (a *App) ClearLogs() LogCleared {
	// 整个清理都在 logMu 内完成：GetLogs 也在这把锁内读历史与代次，
	// 两者因此互斥。分开做的话，并发刷新可能读到「新代次 + 旧历史」
	// 或反过来，表现为清空后日志短暂恢复、顺序错乱。
	a.logMu.Lock()
	defer a.logMu.Unlock()

	var dropped uint64
	if a.mgr != nil {
		dropped = a.mgr.ClearLogs()
	}

	a.logBuf = nil
	a.logBufBytes = 0
	a.logDropped = 0
	a.logDroppedSeq = dropped
	a.logEpoch++

	return LogCleared{Epoch: a.logEpoch}
}
