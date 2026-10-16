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
const maxLogBatch = 200

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
	a.logMu.Lock()
	a.logBuf = append(a.logBuf, line)
	full := len(a.logBuf) >= maxLogBatch
	a.logMu.Unlock()

	// 攒满一批就立刻推，不等下一个时间片：一味等间隔会让日志洪峰时的
	// 延迟随着挤压行数一起增长（队列越长，轮到它越晚）。
	if full {
		select {
		case a.logKick <- struct{}{}:
		default:
			// 推送协程还没处理完上一次通知：它醒来时会一次性取走全部积压。
		}
	}
}

// flushLogs 把队列里攒下的日志行成批推给前端。
func (a *App) flushLogs() {
	if a.ctx == nil {
		return
	}
	a.logMu.Lock()
	if len(a.logBuf) == 0 {
		a.logMu.Unlock()
		return
	}
	batch := a.logBuf
	a.logBuf = nil
	a.logMu.Unlock()

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
