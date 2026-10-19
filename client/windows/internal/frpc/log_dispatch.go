package frpc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// maxLogLines 内存中保留的日志行数。
const maxLogLines = 500

// maxLogBytes 是内存里保留日志的**总字节**上限。
//
// 只限行数不够：单行可以留到 1 MiB（见 pumpLineLimit），500 行就是 500 MiB
// ——而日志洪峰恰恰出现在客户端出问题的时候，那时最不该把内存吃光。
const maxLogBytes = 512 * 1024

// maxLogLineBytes 是单行进入日志缓冲时的保留上限。
//
// 与 pumpLineLimit 是两件事：后者管「读管道时一行最多吞多少」，这里管
// 「进日志缓冲时一行最多占多少」。一行 1 MiB 会自己吃掉整个字节预算，
// 把前面所有有用的行挤出去，而它的信息量并不比前 8 KiB 多。
const maxLogLineBytes = 8 * 1024

// LogEntry 是一条带序号的日志。
type LogEntry struct {
	Seq  uint64
	Text string
}

// Logs 返回日志文本快照。
func (m *Manager) Logs() []string {
	entries := m.LogEntries()
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Text
	}
	return out
}

// LogEntries 返回带序号的日志快照。
func (m *Manager) LogEntries() []LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LogEntry, len(m.logs))
	copy(out, m.logs)
	return out
}

// ClearLogs 清空历史缓冲，返回清空时的日志序号。
//
// 调用方应记下这个序号：清空前产生、清空后才送达的日志行序号不会大于它，
// 据此可以把这些「在途旧行」丢掉，而不是让它们重新出现在界面上。
func (m *Manager) ClearLogs() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 历史、重复合并状态和待投递队列必须同一把锁下清空：只清 logs 的话，
	// 已在途的旧批次会在下一次 dispatch 时重新落进新账号/新页面。
	m.pending = nil
	m.pendingDropped = 0
	m.logs = nil
	m.logBytes = 0
	// 重复行合并状态也要清：留着的话，清空后的第一条日志如果恰好与
	// 清空前那条相同，会被当成「重复」直接吞掉，用户以为清空把新日志也弄没了。
	m.repeatKey = ""
	m.repeatCount = 0
	m.repeatAt = time.Time{}
	return m.logSeq
}

// pumpLineLimit 是单行日志保留的字节上限，超出的部分截断丢弃。
//
// frpc 的正常输出远小于它。超限不是「停止读取」的理由：读取端一旦停摆，
// 管道写满之后子进程就阻塞在写日志上——它既不退出也不响应，Wait 永远
// 不返回，界面上那条隧道会一直是「运行中」。
const pumpLineLimit = 1024 * 1024

func (m *Manager) pump(tunnelID uint, tunnelName string, gen uint64, r io.Reader) {
	// 用 ReadSlice 而不是 bufio.Scanner：Scanner 遇到超过上限的行会返回
	// ErrTooLong 并**停止读取**，剩下的输出没人消费，子进程就卡在写管道上。
	// 这里超限只截断日志内容，读取照常继续到换行、继续跟进后面的行。
	br := bufio.NewReaderSize(r, 64*1024)

	var (
		line      []byte
		truncated bool
	)
	// flush 把攒好的一行交出去。超限的标记只加在日志里，不改变「已经读到
	// 换行」这个事实——后续输出必须继续被消费。
	flush := func() {
		text := string(line)
		if truncated {
			text += "（本行超过 1 MiB，其余内容已截断）"
		}
		m.appendLogGen(tunnelID, tunnelName, gen, text)
		line = line[:0]
		truncated = false
	}

	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			if room := pumpLineLimit - len(line); room > 0 {
				if len(chunk) <= room {
					line = append(line, chunk...)
				} else {
					line = append(line, chunk[:room]...)
					truncated = true
				}
			} else {
				truncated = true
			}
		}

		switch {
		case err == nil:
			flush()
		case errors.Is(err, bufio.ErrBufferFull):
			// 还没读到换行：继续取同一行的后续片段。
			continue
		case errors.Is(err, io.EOF):
			// 最后一行没有换行符，同样要记下来。
			if len(line) > 0 || truncated {
				flush()
			}
			return
		default:
			if len(line) > 0 || truncated {
				flush()
			}
			// 读取失败必须留痕。
			//
			// 以前这里什么都不做：日志会凭空停在某一行，看起来像「frpc 不再
			// 输出了」，而真实原因是我们的读取端坏了（管道错误、卷被卸载）。
			// 这类现象最容易被归因到 frpc 或服务端，实际上问题在客户端自己。
			m.appendLogGen(tunnelID, tunnelName, gen, "日志读取中断："+err.Error())
			return
		}
	}
}

// logRepeatWindow 是同一行连续出现时的合并窗口。
//
// 窗口内只计数不落行；窗口外仍在重复时补一条「重复 N 次」再继续，
// 否则持续压测下日志看起来像停住了。
const logRepeatWindow = 5 * time.Second

// logEntry 是一条已经带好前缀、等待同时写进缓冲并推给前端的日志。
type logEntry struct {
	id   uint
	name string
	gen  uint64
	seq  uint64
	text string
}

// AppendRaw 记录一条由客户端自己格式化好的日志（启动同步、重连说明等）。
//
// 走同一条缓冲与同一个序号：这些行过去只进待推送队列，不进历史记录，
// 于是界面重新加载日志时它们会凭空消失，而它们恰恰是解释「客户端在做什么」
// 的关键信息。
func (m *Manager) AppendRaw(line string) {
	line = strings.TrimRight(line, "\r\n")
	line = clipLogLine(line, maxLogLineBytes)
	if line == "" {
		return
	}

	m.mu.Lock()
	e := logEntry{seq: m.recordTextLocked(line), text: line}
	// 与 appendLog 同理：加锁入队、解锁后由投递协程按序调用回调。
	m.enqueueEmitLocked([]logEntry{e})
	m.mu.Unlock()
}

func (m *Manager) appendLog(tunnelID uint, tunnelName string, line string) {
	m.appendLogGen(tunnelID, tunnelName, 0, line)
}

func (m *Manager) appendLogGen(tunnelID uint, tunnelName string, gen uint64, line string) {
	line = strings.TrimRight(line, "\r\n")
	line = clipLogLine(line, maxLogLineBytes)
	if line == "" {
		return
	}

	now := time.Now()
	key := fmt.Sprintf("%d\x00%s", tunnelID, line)

	m.mu.Lock()
	var out []logEntry
	// 重复窗口结束、或换了一条不同的日志：先把累计的重复次数交代掉。
	if m.repeatCount > 0 && (key != m.repeatKey || now.Sub(m.repeatAt) >= logRepeatWindow) {
		out = append(out, m.recordLocked(m.repeatTunnelID, m.repeatTunnelName, gen,
			fmt.Sprintf("（上一条重复 %d 次，已合并）", m.repeatCount), now))
		m.repeatCount = 0
	}
	if key == m.repeatKey && now.Sub(m.repeatAt) < logRepeatWindow {
		m.repeatCount++
		m.repeatAt = now
		m.enqueueEmitLocked(out)
		m.mu.Unlock()
		return
	}
	m.repeatKey, m.repeatAt = key, now
	m.repeatTunnelID, m.repeatTunnelName = tunnelID, tunnelName
	out = append(out, m.recordLocked(tunnelID, tunnelName, gen, line, now))
	// 加锁入队、解锁后投递：既保证调用方按序号收到，又允许回调重入 Manager。
	m.enqueueEmitLocked(out)
	m.mu.Unlock()
}

// maxPendingEmits 是待投递日志的上限。
//
// 回调极慢时（例如上层在回调里同步做了别的事）队列会堆积；日志本身已有
// 行数与字节上限，这里只需要保证内存不失控，丢弃最旧的即可。
const maxPendingEmits = 4096

// enqueueEmitLocked 在持锁状态下把日志排进投递队列。
func (m *Manager) enqueueEmitLocked(entries []logEntry) {
	if len(entries) == 0 || m.emitWake == nil {
		return
	}
	m.pending = append(m.pending, entries...)
	if over := len(m.pending) - maxPendingEmits; over > 0 {
		m.pending = append(m.pending[:0], m.pending[over:]...)
		m.pendingDropped += over
	}
	select {
	case m.emitWake <- struct{}{}:
	default:
		// 已有待处理的唤醒信号：投递协程醒来会一次取走全部。
	}
}

// dispatchLogs 按入队顺序调用日志回调。
//
// 在锁外调用回调是关键：上层收到「start proxy success」会写一条说明日志，
// 那会再次请求 Manager 的锁；持锁调用就是死锁。
func (m *Manager) dispatchLogs() {
	defer m.emitWG.Done()
	for {
		select {
		case <-m.emitQuit:
			// 退出前把剩余队列排空：进程退出通知产生的收尾日志不该被吞掉。
			m.emitPending()
			return
		case <-m.emitWake:
		}
		m.emitPending()
	}
}

// emitPending 取空当前队列并按序调用回调。
func (m *Manager) emitPending() {
	for {
		m.mu.Lock()
		batch := m.pending
		m.pending = nil
		dropped := m.pendingDropped
		m.pendingDropped = 0
		cb := m.onLog
		m.mu.Unlock()

		if dropped > 0 {
			// seq=0：合成记录不参与去重，前端总是显示。
			batch = append([]logEntry{{
				gen:  0,
				text: fmt.Sprintf("%s  [客户端] 日志过多，已丢弃 %d 条较早的记录",
					time.Now().Format("15:04:05"), dropped),
			}}, batch...)
		}

		if cb != nil {
			for _, e := range batch {
				cb(e.id, e.name, e.seq, e.text)
			}
		}
		m.mu.Lock()
		cbGen := m.onLogGen
		m.mu.Unlock()
		if cbGen != nil {
			for _, e := range batch {
				cbGen(e.id, e.name, e.gen, e.seq, e.text)
			}
		}

		m.mu.Lock()
		more := len(m.pending) > 0 || m.pendingDropped > 0
		m.mu.Unlock()
		if !more {
			return
		}
	}
}

// recordLocked 在已持有锁的前提下写入一行日志，返回可推送的副本。
func (m *Manager) recordLocked(tunnelID uint, tunnelName string, gen uint64, line string, now time.Time) logEntry {
	stamped := fmt.Sprintf("%s  %s  %s", now.Format("15:04:05"), logPrefix(tunnelID, tunnelName), line)
	return logEntry{id: tunnelID, name: tunnelName, gen: gen, seq: m.recordTextLocked(stamped), text: stamped}
}

// recordTextLocked 写入一行已经格式化好的文本，并返回它分配的序号。
func (m *Manager) recordTextLocked(text string) uint64 {
	m.logSeq++
	m.logs = append(m.logs, LogEntry{Seq: m.logSeq, Text: text})
	m.logBytes += len(text)

	// 先按行数裁，再按总字节裁：两个上限针对的是不同的失控方式
	// （行数爆炸 / 单行过大），只留一个都会被另一个绕过。
	if over := len(m.logs) - maxLogLines; over > 0 {
		for i := 0; i < over; i++ {
			m.logBytes -= len(m.logs[i].Text)
		}
		m.logs = m.logs[over:]
	}
	for len(m.logs) > 1 && m.logBytes > maxLogBytes {
		m.logBytes -= len(m.logs[0].Text)
		m.logs = m.logs[1:]
	}
	return m.logSeq
}

// clipLogLine 把超长的单行截断，且不切断多字节字符。
func clipLogLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…（超长，已截断）"
}

// logPrefix 生成日志行的隧道前缀。
//
// 每条隧道一个进程之后，日志区是多个进程输出交织在一起，
// 没有前缀就完全读不出「哪条隧道出了什么问题」。
func logPrefix(tunnelID uint, tunnelName string) string {
	if tunnelName != "" {
		return "Tunnel/" + tunnelName
	}
	return fmt.Sprintf("Tunnel/#%d", tunnelID)
}

// StripLogPrefix 去掉日志行上的「时间 + Tunnel/<名字>」前缀，只留原文。
//
// 前缀由本包的 appendLog 拼成，格式固定为
//
//	<时间>  Tunnel/<名字>  <原文>
//
// 调用方需要看 frpc 原文时（例如判断这行是不是报错）必须先把前缀剥掉：
// 隧道名是用户自己取的，一个叫 errorlog 的隧道不该让它的正常输出被当成错误。
//
// 剥离方式是「跳过时间后的第一个双空格，再找下一个双空格」，而不是直接找
// 最后一个双空格：frpc 自己的输出里也可能出现连续空格，从后面切会把原文
// 截断（例如把 "[mc] start error: x" 截成 "x"），而这段原文正是要给用户看的。
func StripLogPrefix(line string) string {
	afterTime := strings.Index(line, "  ")
	if afterTime < 0 {
		return line
	}
	rest := line[afterTime+2:]
	afterPrefix := strings.Index(rest, "  ")
	if afterPrefix < 0 {
		return line
	}
	return rest[afterPrefix+2:]
}

// IsErrorLine 判断一行 frpc 输出是否表示出错。
//
// frpc 的失败输出形如：
//
//	[W] [client/control.go:172] [run id] [mc] start error: 隧道不存在…
//	[E] [client/service.go:312] login to server failed: …
//
// 它没有结构化字段可用，只能按关键词识别；error / failed 覆盖了它的全部
// 失败路径。判定前先剥掉前缀，避免隧道名本身带出误判。
func IsErrorLine(line string) bool {
	l := strings.ToLower(StripLogPrefix(line))
	return strings.Contains(l, "error") || strings.Contains(l, "failed")
}
