package main

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

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
	if last.text != fmt.Sprintf("line-%d", total-1) {
		t.Fatalf("最新一行必须保留，实际 %q", last.text)
	}
	if first.text == "line-0" {
		t.Fatal("应当丢弃最旧的日志，而不是把全部内容都留着")
	}
}

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

	rest := a.takeLogBatch()
	if len(rest) != total-maxLogBatch {
		t.Fatalf("剩余部分应留到下一轮，实际 %d 行", len(rest))
	}
	if rest[0] != fmt.Sprintf("line-%d", maxLogBatch) {
		t.Fatalf("剩余部分应当接着往后取，实际从 %q 开始", rest[0])
	}
}

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

	if got := shortLine("  短行  "); got != "短行" {
		t.Fatalf("短行应原样返回，实际 %q", got)
	}
}

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
		sum += len(l.text)
	}
	a.logMu.Unlock()

	if lines >= 400 {
		t.Fatal("按字节超限时必须已经丢弃过最旧的行")
	}
	if bytes > maxLogQueueBytes+len(line) {
		t.Fatalf("待推送队列总字节必须有界：实际 %d 字节（上限 %d）", bytes, maxLogQueueBytes)
	}
	if bytes != sum {
		t.Fatalf("字节计数必须与队列内容一致：计数 %d，实际 %d（裁剪时漏减了）", bytes, sum)
	}
}

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

func TestTakeLogBatchOnlyDroppedNotice(t *testing.T) {
	a := &App{}
	a.pushLog(0, "x")
	_ = a.takeLogBatch()

	a.logMu.Lock()
	a.logDropped = 7
	a.logMu.Unlock()

	batch := a.takeLogBatch()
	if len(batch) != 1 || !strings.Contains(batch[0], "已丢弃") {
		t.Fatalf("应只返回一条丢弃提示，实际 %v", batch)
	}
}

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

func TestTakeLogBatchCapturesEpoch(t *testing.T) {
	a := &App{mgr: frpc.New("")}
	a.pushLog(1, "old line")

	items, epoch := a.takeLogBatchWithEpoch()
	if len(items) != 1 || epoch != 0 {
		t.Fatalf("清空前取出的批次代次应为 0，实际 items=%d epoch=%d", len(items), epoch)
	}

	a.ClearLogs()
	a.pushLog(2, "new line")
	items, epoch = a.takeLogBatchWithEpoch()
	if len(items) != 1 || epoch != 1 {
		t.Fatalf("清空后取出的批次代次应为 1，实际 items=%d epoch=%d", len(items), epoch)
	}
}

func TestGetLogsReturnsSeqs(t *testing.T) {
	a := &App{mgr: frpc.New("")}
	a.emitLog("first")
	a.emitLog("second")

	snap := a.GetLogs()
	if len(snap.Seqs) != 2 || len(snap.Lines) != 2 {
		t.Fatalf("序号与文本必须一一对应，实际 seqs=%v lines=%v", snap.Seqs, snap.Lines)
	}
	if snap.Seqs[1] <= snap.Seqs[0] {
		t.Fatalf("序号必须递增，实际 %v", snap.Seqs)
	}
}

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
