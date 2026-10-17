package main

import (
	"fmt"
	"strings"
	"testing"
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
		a.pushLog(fmt.Sprintf("line-%d", i))
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
		a.pushLog(fmt.Sprintf("line-%d", i))
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

// TestTakeLogBatchReportsDropped 覆盖「静默丢弃」。
//
// 悄悄丢日志比丢日志本身更糟：用户会以为自己看到了完整的现场，
// 然后拿一段缺失的日志去判断故障。
func TestTakeLogBatchReportsDropped(t *testing.T) {
	a := &App{}
	for i := 0; i < maxLogQueue+500; i++ {
		a.pushLog(fmt.Sprintf("line-%d", i))
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
