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

const maxLogLines = 500

const maxLogBytes = 512 * 1024

const maxLogLineBytes = 8 * 1024

type LogEntry struct {
	Seq  uint64
	Text string
}

func (m *Manager) Logs() []string {
	entries := m.LogEntries()
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Text
	}
	return out
}

func (m *Manager) LogEntries() []LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LogEntry, len(m.logs))
	copy(out, m.logs)
	return out
}

func (m *Manager) ClearLogs() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = nil
	m.pendingDropped = 0
	m.logs = nil
	m.logBytes = 0
	m.repeatKey = ""
	m.repeatCount = 0
	m.repeatAt = time.Time{}
	return m.logSeq
}

const pumpLineLimit = 1024 * 1024

func (m *Manager) pump(tunnelID uint, tunnelName string, r io.Reader) {
	m.pumpGen(tunnelID, tunnelName, 0, r)
}

func (m *Manager) pumpGen(tunnelID uint, tunnelName string, gen uint64, r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)

	var (
		line      []byte
		truncated bool
	)
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
			continue
		case errors.Is(err, io.EOF):
			if len(line) > 0 || truncated {
				flush()
			}
			return
		default:
			if len(line) > 0 || truncated {
				flush()
			}
			m.appendLogGen(tunnelID, tunnelName, gen, "日志读取中断："+err.Error())
			return
		}
	}
}

const logRepeatWindow = 5 * time.Second

type logEntry struct {
	id   uint
	name string
	gen  uint64
	seq  uint64
	text string
	acct uint64
}

func (m *Manager) AppendRaw(line string) {
	m.AppendRawAccount(0, line)
}

func (m *Manager) AppendRawAccount(acct uint64, line string) {
	line = strings.TrimRight(line, "\r\n")
	line = clipLogLine(line, maxLogLineBytes)
	if line == "" {
		return
	}

	m.mu.Lock()
	e := logEntry{seq: m.recordTextLocked(line), text: line, acct: acct}
	m.enqueueEmitLocked([]logEntry{e})
	m.mu.Unlock()
}

func (m *Manager) RecordLine(text string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordTextLocked(text)
}

func (m *Manager) appendLog(tunnelID uint, tunnelName string, line string) {
	m.appendLogGen(tunnelID, tunnelName, 0, line)
}

func (m *Manager) appendLogGen(tunnelID uint, tunnelName string, gen uint64, line string) {
	if gen != 0 && !m.stillCurrent(tunnelID, gen) {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	line = clipLogLine(line, maxLogLineBytes)
	if line == "" {
		return
	}

	now := time.Now()
	key := fmt.Sprintf("%d\x00%d\x00%s", gen, tunnelID, line)

	m.mu.Lock()
	var out []logEntry
	if m.repeatCount > 0 && (key != m.repeatKey || now.Sub(m.repeatAt) >= logRepeatWindow) {
		out = append(out, m.recordLocked(m.repeatTunnelID, m.repeatTunnelName, m.repeatGen,
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
	m.repeatGen = gen
	out = append(out, m.recordLocked(tunnelID, tunnelName, gen, line, now))
	m.enqueueEmitLocked(out)
	m.mu.Unlock()
}

const maxPendingEmits = 4096

func (m *Manager) enqueueEmitLocked(entries []logEntry) {
	if len(entries) == 0 || m.emitWake == nil {
		return
	}
	m.pending = append(m.pending, entries...)
	if over := len(m.pending) - maxPendingEmits; over > 0 {
		m.pending = append(m.pending[:0], m.pending[over:]...)
		m.pendingDropped += over
	}
	if m.pendingDropped > 0 {
		dropped := m.pendingDropped
		m.pendingDropped = 0
		msg := fmt.Sprintf("%s  [客户端] 日志过多，已丢弃 %d 条较早的记录",
			time.Now().Format("15:04:05"), dropped)
		m.pending = append(m.pending, logEntry{seq: m.recordTextLocked(msg), text: msg})
	}
	select {
	case m.emitWake <- struct{}{}:
	default:
	}
}

func (m *Manager) dispatchLogs() {
	defer m.emitWG.Done()
	for {
		select {
		case <-m.emitQuit:
			m.emitPending()
			return
		case <-m.emitWake:
		}
		m.emitPending()
	}
}

func (m *Manager) emitPending() {
	for {
		m.mu.Lock()
		batch := m.pending
		m.pending = nil
		cb := m.onLog
		cbGen := m.onLogGen
		cbAcct := m.onLogAcct
		m.mu.Unlock()

		switch {
		case cbAcct != nil:
			for _, e := range batch {
				cbAcct(e.acct, e.id, e.name, e.gen, e.seq, e.text)
			}
		case cbGen != nil:
			for _, e := range batch {
				cbGen(e.id, e.name, e.gen, e.seq, e.text)
			}
		case cb != nil:
			for _, e := range batch {
				cb(e.id, e.name, e.seq, e.text)
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

func (m *Manager) recordLocked(tunnelID uint, tunnelName string, gen uint64, line string, now time.Time) logEntry {
	stamped := fmt.Sprintf("%s  %s  %s", now.Format("15:04:05"), logPrefix(tunnelID, tunnelName), line)
	return logEntry{id: tunnelID, name: tunnelName, gen: gen, seq: m.recordTextLocked(stamped),
		text: stamped, acct: m.accounts[tunnelID]}
}

func (m *Manager) recordTextLocked(text string) uint64 {
	m.logSeq++
	m.logs = append(m.logs, LogEntry{Seq: m.logSeq, Text: text})
	m.logBytes += len(text)

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

func logPrefix(tunnelID uint, tunnelName string) string {
	if tunnelName != "" {
		return "Tunnel/" + tunnelName
	}
	return fmt.Sprintf("Tunnel/#%d", tunnelID)
}

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

func IsErrorLine(line string) bool {
	l := strings.ToLower(StripLogPrefix(line))
	return strings.Contains(l, "error") || strings.Contains(l, "failed")
}
