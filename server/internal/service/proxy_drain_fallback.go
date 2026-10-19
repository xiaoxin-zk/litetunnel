package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	proxyDrainFallbackLimit = 512
)

type proxyDrainFallback struct {
	req      proxyDrainRequest
	at       time.Time
	attempts int
}

type proxyDrainFallbackQueue struct {
	mu            sync.Mutex
	items         map[uint]*proxyDrainFallback
	dropped       atomic.Int64
	droppedItems  []proxyDrainFallback
	walPath       string
	walLegacyPath string
	persisted     atomic.Int64
	enqueued      atomic.Int64
}

func newProxyDrainFallbackQueue() *proxyDrainFallbackQueue {
	path := proxyDrainWALPath()
	q := &proxyDrainFallbackQueue{
		items:         make(map[uint]*proxyDrainFallback),
		walPath:       path,
		walLegacyPath: filepath.Join(filepath.Dir(path), "proxy-drain-dropped.jsonl"),
	}
	q.loadFromWAL()
	return q
}

func proxyDrainWALPath() string {
	if p := strings.TrimSpace(os.Getenv("LT_PROXY_DRAIN_WAL")); p != "" {
		return p
	}
	for _, dir := range []string{"/data", "/var/lib/litetunnel"} {
		if dirWritable(dir) {
			return filepath.Join(dir, "proxy-drain-outbox.jsonl")
		}
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "litetunnel", "proxy-drain-outbox.jsonl")
	}
	return filepath.Join(os.TempDir(), "litetunnel", "proxy-drain-outbox.jsonl")
}

func dirWritable(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".lt-drain-wal-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

type proxyDrainWALRecord struct {
	Kind        string             `json:"kind,omitempty"`
	UserID      uint               `json:"user_id"`
	Incarnation string             `json:"incarnation,omitempty"`
	Prefix      string             `json:"prefix"`
	Gen         uint64             `json:"gen,omitempty"`
	NotAfter    time.Time          `json:"not_after,omitempty"`
	Deleted     bool               `json:"deleted,omitempty"`
	Attempts    int                `json:"attempts,omitempty"`
	Known       []proxyDrainTarget `json:"known,omitempty"`
	Intent      string             `json:"intent,omitempty"`
	NoRegister  bool               `json:"no_register,omitempty"`
	At          time.Time          `json:"at"`
}

func (r proxyDrainWALRecord) request() proxyDrainRequest {
	return proxyDrainRequest{
		userID:      r.UserID,
		prefix:      r.Prefix,
		gen:         r.Gen,
		notAfter:    r.NotAfter,
		deleted:     r.Deleted,
		attempts:    r.Attempts,
		known:       r.Known,
		intent:      r.Intent,
		noRegister:  r.NoRegister,
		incarnation: r.Incarnation,
	}
}

func walRecordOf(it proxyDrainFallback) proxyDrainWALRecord {
	return proxyDrainWALRecord{
		Incarnation: it.req.incarnation,
		UserID:      it.req.userID,
		Prefix:      it.req.prefix,
		Gen:         it.req.gen,
		NotAfter:    it.req.notAfter,
		Deleted:     it.req.deleted,
		Attempts:    it.req.attempts,
		Known:       it.req.known,
		Intent:      it.req.intent,
		NoRegister:  it.req.noRegister,
		At:          it.at,
	}
}

func (q *proxyDrainFallbackQueue) enqueue(req proxyDrainRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.enqueued.Add(1)
	if _, ok := q.items[req.userID]; !ok && len(q.items) >= proxyDrainFallbackLimit {
		var oldest uint
		var oldestAt time.Time
		first := true
		for id, it := range q.items {
			if first || it.at.Before(oldestAt) {
				oldest, oldestAt, first = id, it.at, false
			}
		}
		oldestIt := q.items[oldest]
		delete(q.items, oldest)
		q.dropped.Add(1)
		q.rememberDropped(*oldestIt)
		log.Printf("[proxy-drain] 补偿队列已满（%d），丢弃用户 %d 的最旧意图（数据库恢复后自动补写，名单见 drain_fallback.dropped_recent）",
			proxyDrainFallbackLimit, oldest)
	}
	next := &proxyDrainFallback{req: req, at: time.Now()}
	if cur, ok := q.items[req.userID]; ok && !next.supersedes(*cur) {
		log.Printf("[proxy-drain] 丢弃过期的断流意图（用户 %d：%s 早于队列中已有代次 %d）",
			req.userID, describeDrainIntent(req), cur.req.gen)
		return
	}
	q.items[req.userID] = next
	q.persistAllLocked()
}

func (a proxyDrainFallback) supersedes(b proxyDrainFallback) bool {
	if a.req.deleted != b.req.deleted {
		return a.req.deleted
	}
	if a.req.gen != b.req.gen {
		return a.req.gen > b.req.gen
	}
	if !a.req.notAfter.Equal(b.req.notAfter) {
		return a.req.notAfter.After(b.req.notAfter)
	}
	return a.req.intent >= b.req.intent
}

func describeDrainIntent(req proxyDrainRequest) string {
	kind := "禁用"
	if req.deleted {
		kind = "删号"
	}
	return fmt.Sprintf("%s(generation=%d)", kind, req.gen)
}

func (q *proxyDrainFallbackQueue) take() []proxyDrainFallback {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	out := make([]proxyDrainFallback, 0, len(q.items))
	for id, it := range q.items {
		out = append(out, *it)
		delete(q.items, id)
	}
	return out
}

func (q *proxyDrainFallbackQueue) putBack(it proxyDrainFallback) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= proxyDrainFallbackLimit {
		q.dropped.Add(1)
		q.rememberDropped(it)
		log.Printf("[proxy-drain] 补偿队列已满（%d），用户 %d 的断流意图未能放回（数据库恢复后自动补写）",
			proxyDrainFallbackLimit, it.req.userID)
		return
	}
	q.items[it.req.userID] = &proxyDrainFallback{req: it.req, at: it.at, attempts: it.attempts + 1}
	q.persistAllLocked()
}

const droppedRecentMax = 16

func (q *proxyDrainFallbackQueue) rememberDropped(it proxyDrainFallback) {
	if len(q.droppedItems) >= droppedRecentMax {
		q.droppedItems = q.droppedItems[1:]
	}
	q.droppedItems = append(q.droppedItems, it)
	q.persistAllLocked()
}

func (q *proxyDrainFallbackQueue) takeDropped() []proxyDrainFallback {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.droppedItems
	q.droppedItems = nil
	return out
}

const proxyDrainWALMaxBytes = 4 << 20

func (q *proxyDrainFallbackQueue) loadFromWAL() {
	if q.walPath == "" {
		return
	}
	queued, dropped := q.readWAL(q.walPath)
	if queued+dropped == 0 && q.walLegacyPath != "" && q.walLegacyPath != q.walPath {
		_, dropped = q.readWAL(q.walLegacyPath)
	}
	if queued > 0 {
		log.Printf("[proxy-drain] 从 WAL 读回 %d 条等待补写的断流意图（%s），数据库可用后会自动补写",
			queued, q.walPath)
	}
	if dropped > 0 {
		q.dropped.Add(int64(dropped))
		log.Printf("[proxy-drain] 从 WAL 读回 %d 条被淘汰的断流意图（%s），将尝试补写回库",
			dropped, q.walPath)
	}
}

func (q *proxyDrainFallbackQueue) readWAL(path string) (queued, dropped int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, proxyDrainWALMaxBytes))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec proxyDrainWALRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.UserID == 0 {
			continue
		}
		at := rec.At
		if at.IsZero() {
			at = time.Now()
		}
		it := proxyDrainFallback{req: rec.request(), at: at, attempts: rec.Attempts}
		if rec.Kind == "queued" {
			if _, ok := q.items[rec.UserID]; !ok && len(q.items) >= proxyDrainFallbackLimit {
				continue
			}
			q.items[rec.UserID] = &it
			queued++
			continue
		}
		if len(q.droppedItems) >= droppedRecentMax {
			q.droppedItems = q.droppedItems[1:]
		}
		q.droppedItems = append(q.droppedItems, it)
		dropped++
	}
	return queued, dropped
}

func (q *proxyDrainFallbackQueue) persistAll() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.persistAllLocked()
}

func (q *proxyDrainFallbackQueue) persistAllLocked() {
	if q.walPath == "" {
		return
	}
	dir := filepath.Dir(q.walPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("[proxy-drain] 创建断流兜底 WAL 目录失败（重启后这些意图会丢失）: %v", err)
		return
	}
	tmp := q.walPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("[proxy-drain] 写断流兜底 WAL 失败（重启后这些意图会丢失）: %v", err)
		return
	}
	w := bufio.NewWriter(f)
	writeOne := func(it proxyDrainFallback, kind string) bool {
		rec := walRecordOf(it)
		rec.Kind = kind
		b, err := json.Marshal(rec)
		if err != nil {
			log.Printf("[proxy-drain] 断流兜底 WAL 记录编码失败（用户 %d，跳过）: %v", it.req.userID, err)
			return true
		}
		if _, err := w.Write(b); err != nil {
			return false
		}
		return w.WriteByte('\n') == nil
	}
	for _, it := range q.items {
		if !writeOne(*it, "queued") {
			break
		}
	}
	for _, it := range q.droppedItems {
		if !writeOne(it, "dropped") {
			break
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		log.Printf("[proxy-drain] 写断流兜底 WAL 失败（重启后这些意图会丢失）: %v", err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, q.walPath); err != nil {
		_ = os.Remove(tmp)
		log.Printf("[proxy-drain] 替换断流兜底 WAL 失败（重启后这些意图会丢失）: %v", err)
	}
}

func (q *proxyDrainFallbackQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

type ProxyDrainFallbackStats struct {
	Queued        int    `json:"queued"`
	Enqueued      int64  `json:"enqueued"`
	Persisted     int64  `json:"persisted"`
	Dropped       int64  `json:"dropped"`
	DroppedRecent []uint `json:"dropped_recent,omitempty"`
	WALPath       string `json:"wal_path,omitempty"`
}

func (s *Services) ProxyDrainFallback() ProxyDrainFallbackStats {
	if s == nil || s.drainFallback == nil {
		return ProxyDrainFallbackStats{}
	}
	q := s.drainFallback
	q.mu.Lock()
	recent := make([]uint, 0, len(q.droppedItems))
	for _, it := range q.droppedItems {
		recent = append(recent, it.req.userID)
	}
	q.mu.Unlock()
	return ProxyDrainFallbackStats{
		Queued:        q.size(),
		Enqueued:      q.enqueued.Load(),
		Persisted:     q.persisted.Load(),
		Dropped:       q.dropped.Load(),
		DroppedRecent: recent,
		WALPath:       q.walPath,
	}
}

func (s *Services) flushProxyDrainFallback() {
	if s == nil || s.drainFallback == nil || s.DB == nil {
		return
	}
	pending := s.drainFallback.take()
	pending = append(pending, s.drainFallback.takeDropped()...)
	if len(pending) == 0 {
		return
	}
	for _, it := range pending {
		if fence := s.recordProxyDrainPending(it.req); fence != "" {
			s.drainFallback.persisted.Add(1)
			log.Printf("[proxy-drain] 用户 %d 的断流意图已补写回库（数据库已恢复），交由后台重试器执行", it.req.userID)
			continue
		}
		s.drainFallback.putBack(it)
	}
	s.drainFallback.persistAll()
}
