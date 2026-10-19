package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

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

func (a *App) emitLog(msg string) {
	a.emitLogEpoch(a.captureEpoch(), msg)
}

func (a *App) emitLogEpoch(acct accountEpoch, msg string) {
	if a.mgr == nil {
		return
	}
	if !a.epochCurrent(acct) {
		return
	}
	a.mgr.AppendRawAccount(uint64(acct), time.Now().Format("15:04:05")+"  "+msg)
}

func (a *App) emitTunnelLog(name, msg string) {
	a.emitTunnelLogEpoch(a.captureEpoch(), name, msg)
}

func (a *App) emitTunnelLogEpoch(acct accountEpoch, name, msg string) {
	if a.mgr == nil {
		return
	}
	if !a.epochCurrent(acct) {
		return
	}
	a.mgr.AppendRawAccount(uint64(acct),
		fmt.Sprintf("%s  Tunnel/%s  %s", time.Now().Format("15:04:05"), name, msg))
}

type pendingLog struct {
	acct accountEpoch
	seq  uint64
	text string
}

const maxLogBatch = 200

const maxLogQueue = 2000

const maxLogQueueBytes = 1024 * 1024

const maxLogBatchBytes = 128 * 1024

const logFlushInterval = 120 * time.Millisecond

func (a *App) appendLogLineAcct(acct accountEpoch, seq uint64, line string) bool {
	if a.ctx == nil {
		return false
	}
	accepted, batchReady := a.pushLogAcct(acct, seq, line)
	if !accepted {
		return false
	}
	if batchReady {
		select {
		case a.logKick <- struct{}{}:
		default:
		}
	}
	return true
}

func (a *App) pushLog(seq uint64, line string) (accepted, batchReady bool) {
	return a.pushLogAcct(a.captureEpoch(), seq, line)
}

func (a *App) pushLogAcct(acct accountEpoch, seq uint64, line string) (accepted, batchReady bool) {
	if acct.known() && !a.epochCurrent(acct) {
		return false, false
	}

	a.logMu.Lock()
	defer a.logMu.Unlock()

	if seq != 0 && seq <= a.logDroppedSeq {
		return false, false
	}

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

	a.logBuf = append(a.logBuf, pendingLog{acct: acct, seq: seq, text: line})
	a.logBufBytes += len(line)
	return true, len(a.logBuf) >= maxLogBatch
}

func (a *App) takeLogBatch() []string {
	items, _ := a.takeLogBatchWithEpoch()
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.text
	}
	return out
}

func (a *App) dropForeignLogsLocked(cur accountEpoch) {
	kept := a.logBuf[:0]
	for _, it := range a.logBuf {
		if it.acct.known() && it.acct != cur {
			a.logBufBytes -= len(it.text)
			continue
		}
		kept = append(kept, it)
	}
	a.logBuf = kept
}

func (a *App) takeLogBatchWithEpoch() ([]pendingLog, uint64) {
	acct := a.captureEpoch()

	a.logMu.Lock()
	defer a.logMu.Unlock()

	a.dropForeignLogsLocked(acct)

	if len(a.logBuf) == 0 && a.logDropped == 0 {
		return nil, a.logEpoch
	}

	n := len(a.logBuf)
	if n > maxLogBatch {
		n = maxLogBatch
	}

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

	batch := make([]pendingLog, 0, n+1)
	if a.logDropped > 0 {
		msg := fmt.Sprintf("%s  [客户端] 日志积压，已丢弃 %d 行较早的记录",
			time.Now().Format("15:04:05"), a.logDropped)
		var seq uint64
		if a.mgr != nil {
			seq = a.mgr.RecordLine(msg)
		}
		batch = append(batch, pendingLog{seq: seq, text: msg})
		a.logDropped = 0
	}
	for i := 0; i < n; i++ {
		batch = append(batch, a.logBuf[i])
		a.logBufBytes -= len(a.logBuf[i].text)
	}

	a.logBuf = a.logBuf[n:]
	return batch, a.logEpoch
}

func (a *App) currentLogEpoch() uint64 {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	return a.logEpoch
}

type logBatchEvent struct {
	Epoch uint64   `json:"epoch"`
	Seqs  []uint64 `json:"seqs"`
	Lines []string `json:"lines"`
}

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

func (a *App) startLogFlusher() {
	a.logWg.Add(1)
	go func() {
		defer a.logWg.Done()
		ticker := time.NewTicker(logFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-a.logKick:
			case <-a.logStop:
				a.flushLogs()
				return
			}
			a.flushLogs()
		}
	}()
}

type LogSnapshot struct {
	Epoch uint64   `json:"epoch"`
	Seqs  []uint64 `json:"seqs"`
	Lines []string `json:"lines"`
}

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

type LogCleared struct {
	Epoch uint64 `json:"epoch"`
}

func (a *App) ClearLogs() LogCleared {
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
