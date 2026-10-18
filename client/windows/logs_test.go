package main

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

// TestLogQueueDropsOldestAndCounts 覆盖「待推送队列无界增长」。
//
// 原先 logBuf 只增不减：前端消费慢、frpc 又持续刷日志时它会一直涨，
// 而日志洪峰恰恰出现在客户端出问题的时候——那时最不该再把内存吃光。
// 触顶后要丢**最旧**的：日志是有时效的，留下最近的才能解释「刚才发生了什么」。
func TestLogQueueDropsOldestAndCounts(t *testing.T) {
	a := &App{}
	const total = maxLogQueue + 1000
	for i := 0; i < total; i++ {
		a.pushLog(0, fmt.Sprintf("line-%d", i))
	}

	a.logMu.Lock()
	remain := len(a.logBuf)
	dropped := a.logDropped
	first, last := a.logBuf[0], a.logBuf[remain-1]
	a.logMu.Unlock()

	if remain > maxLogQueue {
		t.Fatalf("队列必须有界，实际 %d 行（上限 %d）", remain, maxLogQueue)
	}
	if dropped == 0 {
		t.Fatal("超过上限时必须真的丢弃，否则上限等于没设")
	}
	if dropped != total-remain {
		t.Fatalf("丢弃数与「总推送 - 现存」应当一致：dropped=%d total=%d remain=%d",
			dropped, total, remain)
	}
	// 最新一行必须保留，最早那行必须已经没了。
	if last != fmt.Sprintf("line-%d", total-1) {
		t.Fatalf("最新一行必须保留，实际 %q", last)
	}
	if first == "line-0" {
		t.Fatal("应当丢弃最旧的日志，而不是把全部内容都留着")
	}
}

// TestTakeLogBatchCapsAtMaxLogBatch 覆盖「单次事件大小没有上界」。
//
// maxLogBatch 原先只用来触发 flush，flush 时却一次取走整个队列：积压越久，
// 单次事件就越大，于是「一批最多 200 行」这个上限根本没生效——前端仍然要在
// 一次事件里处理几千行。
func TestTakeLogBatchCapsAtMaxLogBatch(t *testing.T) {
	a := &App{}
	const total = maxLogBatch + 50
	for i := 0; i < total; i++ {
		a.pushLog(0, fmt.Sprintf("line-%d", i))
	}

	batch := a.takeLogBatch()
	if len(batch) != maxLogBatch {
		t.Fatalf("单次推送不能超过 %d 行，实际 %d 行", maxLogBatch, len(batch))
	}
	if batch[0] != "line-0" || batch[len(batch)-1] != fmt.Sprintf("line-%d", maxLogBatch-1) {
		t.Fatalf("应当按先后顺序取最旧的 %d 行，实际从 %q 到 %q",
			maxLogBatch, batch[0], batch[len(batch)-1])
	}

	// 剩下的必须留到下一轮，不能被这一轮顺手丢掉。
	rest := a.takeLogBatch()
	if len(rest) != total-maxLogBatch {
		t.Fatalf("剩余部分应留到下一轮，实际 %d 行", len(rest))
	}
	if rest[0] != fmt.Sprintf("line-%d", maxLogBatch) {
		t.Fatalf("剩余部分应当接着往后取，实际从 %q 开始", rest[0])
	}
}

// TestShortLineKeepsValidUTF8 覆盖「按字节硬切中文」。
//
// 直接 s[:64] 会切在 UTF-8 字符中间：中文 22 个字就到 64 字节，
// 「隧道名 + 中文说明」这类行经常正好落在切口上，日志里显示成半个乱码（�）。
func TestShortLineKeepsValidUTF8(t *testing.T) {
	s := shortLine(strings.Repeat("中文隧道说明", 10))
	if !utf8.ValidString(s) {
		t.Fatalf("截断后必须是合法 UTF-8，实际 %q", s)
	}
	if !strings.HasSuffix(s, "…") {
		t.Fatalf("超长行应带省略号，实际 %q", s)
	}
	if len(strings.TrimSuffix(s, "…")) > 64 {
		t.Fatalf("截断后仍超过 64 字节：%d", len(s))
	}

	// 短行保持原样（只去首尾空白）。
	if got := shortLine("  短行  "); got != "短行" {
		t.Fatalf("短行应原样返回，实际 %q", got)
	}
}

// TestLogQueueRespectsByteBudget 覆盖「只数行数挡不住大日志」。
//
// 单行在 frpc 那边可以留到 1 MiB，2000 行就是 2 GiB——行数上限看起来在，
// 内存照样能被吃光。字节预算与行数预算同时生效，谁先到按谁裁。
func TestLogQueueRespectsByteBudget(t *testing.T) {
	a := &App{}
	line := strings.Repeat("x", 8*1024)
	for i := 0; i < 400; i++ {
		a.pushLog(0, line)
	}

	a.logMu.Lock()
	bytes, lines := a.logBufBytes, len(a.logBuf)
	sum := 0
	for _, l := range a.logBuf {
		sum += len(l)
	}
	a.logMu.Unlock()

	if lines >= 400 {
		t.Fatal("按字节超限时必须已经丢弃过最旧的行")
	}
	// 允许最后一行的溢出：是否丢弃是在入队**之前**判断的。
	if bytes > maxLogQueueBytes+len(line) {
		t.Fatalf("待推送队列总字节必须有界：实际 %d 字节（上限 %d）", bytes, maxLogQueueBytes)
	}
	if bytes != sum {
		t.Fatalf("字节计数必须与队列内容一致：计数 %d，实际 %d（裁剪时漏减了）", bytes, sum)
	}
}

// TestTakeLogBatchRespectsByteBudget 覆盖「单次事件过大」。
//
// 200 行 × 1 MiB 的事件要序列化、跨进程传、再在 JS 里处理，会把 Wails
// 那条桥堵住很久。行数之外还要有字节上限；但单行本身就超预算时仍要发出去，
// 否则队列永远清不空。
func TestTakeLogBatchRespectsByteBudget(t *testing.T) {
	a := &App{}
	line := strings.Repeat("y", 16*1024)
	for i := 0; i < 50; i++ {
		a.pushLog(0, line)
	}

	batch := a.takeLogBatch()
	total := 0
	for _, l := range batch {
		total += len(l)
	}
	if len(batch) == 0 {
		t.Fatal("有积压时不该返回空批次")
	}
	if total > maxLogBatchBytes {
		t.Fatalf("单次推送总字节必须有界：实际 %d（上限 %d）", total, maxLogBatchBytes)
	}

	single := &App{}
	huge := strings.Repeat("z", maxLogBatchBytes+1)
	single.pushLog(0, huge)
	if got := single.takeLogBatch(); len(got) != 1 || got[0] != huge {
		t.Fatalf("单行超过批次预算时也必须发出去，否则队列永远清不空（实际 %d 行）", len(got))
	}
}

// TestTakeLogBatchOnlyDroppedNotice 覆盖「队列已空、只剩丢弃提示」。
//
// 这时 batch 里只有那行提示，取行逻辑不能按「至少取一行」去碰空队列——
// 越界取会让整个客户端崩在日志推送协程里，而且崩得毫无征兆。
func TestTakeLogBatchOnlyDroppedNotice(t *testing.T) {
	a := &App{}
	a.pushLog(0, "x")
	_ = a.takeLogBatch() // 先清空队列

	a.logMu.Lock()
	a.logDropped = 7
	a.logMu.Unlock()

	batch := a.takeLogBatch()
	if len(batch) != 1 || !strings.Contains(batch[0], "已丢弃") {
		t.Fatalf("应只返回一条丢弃提示，实际 %v", batch)
	}
}

// TestTakeLogBatchReportsDropped 覆盖「静默丢弃」。
//
// 悄悄丢日志比丢日志本身更糟：用户会以为自己看到了完整的现场，
// 然后拿一段缺失的日志去判断故障。
func TestTakeLogBatchReportsDropped(t *testing.T) {
	a := &App{}
	for i := 0; i < maxLogQueue+500; i++ {
		a.pushLog(0, fmt.Sprintf("line-%d", i))
	}

	a.logMu.Lock()
	dropped := a.logDropped
	a.logMu.Unlock()
	if dropped == 0 {
		t.Fatal("前置条件：这么多行之后应当已经发生丢弃")
	}

	batch := a.takeLogBatch()
	if len(batch) == 0 {
		t.Fatal("有积压时不该返回空批次")
	}
	if !strings.Contains(batch[0], "已丢弃") || !strings.Contains(batch[0], fmt.Sprint(dropped)) {
		t.Fatalf("首行应当说明丢弃了多少行，实际 %q（dropped=%d）", batch[0], dropped)
	}

	// 提示只报一次：下一批里不该再出现。
	for _, line := range a.takeLogBatch() {
		if strings.Contains(line, "已丢弃") {
			t.Fatalf("丢弃提示不该在每一批里重复，实际 %q", line)
		}
	}
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if a.logDropped != 0 {
		t.Fatalf("提示发出后计数应当归零，实际 %d", a.logDropped)
	}
}

// TestClearLogsDropsPendingQueue 覆盖「点了清空，日志又自己冒回来」。
//
// 清空只清历史记录是不够的：清空前已经攒在待推送队列里、还没发出去的行，
// 会在下一次 flush 时照常出现在界面上。
func TestClearLogsDropsPendingQueue(t *testing.T) {
	a := &App{mgr: frpc.New("")}
	a.pushLog(0, "before clear")
	a.ClearLogs()
	if batch := a.takeLogBatch(); len(batch) != 0 {
		t.Fatalf("清空后不该再推出旧行，实际 %v", batch)
	}

	a.pushLog(0, "after clear")
	batch := a.takeLogBatch()
	if len(batch) != 1 || batch[0] != "after clear" {
		t.Fatalf("清空后的新行应保留，实际 %v", batch)
	}
}

// TestClearLogsDropsInFlightLines 覆盖「清空前产生的行清空后才送达」。
//
// 回调在 Manager 解锁之后才执行，所以这些行完全可能晚于清空进入队列。
// 只清缓冲挡不住它们，必须靠序号识别。
func TestClearLogsDropsInFlightLines(t *testing.T) {
	a := &App{mgr: frpc.New("")}
	a.mgr.AppendRaw("old line")
	cleared := a.ClearLogs()

	a.pushLog(1, "stale line")
	if batch := a.takeLogBatch(); len(batch) != 0 {
		t.Fatalf("清空前的在途行不该重新出现，实际 %v", batch)
	}
	if cleared.Epoch == 0 {
		t.Fatal("清空后必须递增代次，供前端丢弃旧批次")
	}
	a.pushLog(2, "fresh line")
	if batch := a.takeLogBatch(); len(batch) != 1 || batch[0] != "fresh line" {
		t.Fatalf("清空后的新行应保留，实际 %v", batch)
	}
}

// TestGetLogsIncludesClientLines 覆盖「客户端自身日志不在历史快照里」。
//
// 启动同步、重连说明过去只进待推送队列，不进历史；界面重新加载日志后
// 这些行就消失了，而它们正是解释「客户端在做什么」的关键。
func TestGetLogsIncludesClientLines(t *testing.T) {
	a := &App{mgr: frpc.New("")}
	a.emitLog("启动同步完成：2 条隧道运行中")
	a.emitTunnelLog("mc", "隧道已断开")

	snap := a.GetLogs()
	if len(snap.Lines) != 2 {
		t.Fatalf("快照应同时包含客户端与隧道说明，实际 %v", snap.Lines)
	}
	if !strings.Contains(snap.Lines[0], "启动同步完成") {
		t.Fatalf("客户端说明缺失: %v", snap.Lines)
	}
	if !strings.Contains(snap.Lines[1], "Tunnel/mc") {
		t.Fatalf("隧道说明缺失: %v", snap.Lines)
	}
}
