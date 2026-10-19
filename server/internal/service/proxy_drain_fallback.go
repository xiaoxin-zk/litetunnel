package service

// 本文件是「断流待办登记失败」的**进程内兜底**（缺陷 4）。
//
// # 它补的是什么洞
//
// 断流意图已经改成「先落库、再动手」（见 proxy_drain_retry.go 的
// recordProxyDrainPending），删号路径更进一步：意图与删除在同一个事务里
// （见 account_lifecycle.go 的 recordPurgeIntentsTx）。这两处覆盖了绝大多数
// 场景，但仍有三种情况下**意图根本没进库**：
//
//  1. 数据库整体不可用（连接池耗尽、主库切换、SQLite 文件被占用）——
//     recordProxyDrainPending 返回空串；
//  2. 未配置 frps 管理接口——压根没有断流手段（这条是静态配置问题，
//     见下面的说明，不进队列）；
//  3. rescheduleProxyDrain 时发现 req.intent 为空（同上，登记失败）。
//
// 这三种情况下，如果本次也没关干净，残留代理就**只剩下日志里那一行**。
// 而日志会被滚动掉，重启后没有任何线索能找回「这个账号的代理可能还在跑」
// ——这正是缺陷 4 的形态。
//
// # 为什么是内存队列 + 落盘镜像，而不是再写一张表
//
// 「写一张表」在当前故障下不可行：进队列的前提就是**数据库写不进去**。
// 能做的只有把意图留在内存里，等数据库恢复后补写；同时把**整条队列**
// 镜像到 WAL 文件，让进程重启后还能读回来。
//
// 早先只有「被淘汰的意图」落盘，正常排队的那批仍只在内存里。这在容器里
// 尤其危险：数据库抖十秒就够让几十上百条意图只活在内存中，而一次重启
// （滚动升级、OOM、docker restart）会把它们全部抹掉——恰恰是故障最容易
// 触发重启的时候。
//
// 代价要说清楚：
//
//   - WAL 是**同目录整体重写**（临时文件 + rename）：崩溃不会留下半行
//     JSON，但整体重写的开销随队列长度线性增长。队列上限 512 条、
//     每次重写几十到上百 KB，而它只发生在数据库已经写不进去的故障期，
//     这个代价可以接受；为它去做追加/截断的偏移量维护不值得。
//   - 队列有界：数据库长时间不可用时意图会不断堆积，无界就是内存泄漏。
//     满了之后**丢弃最旧的**并记指标——最新的意图更接近当前真实状态
//     （账号可能已经被重新启用），保留它比保留一条陈旧的更有价值。
//   - WAL 里是账号 ID 与前缀，不含密码/token，权限仍按 0600 收敛。
//
// # 为什么未配置 frps 不进队列
//
// 那不是「暂时失败」，而是「这个部署根本没有断流手段」。重试一万次也不会
// 成功，进队列只会让内存慢慢涨满并刷日志。它需要的是**启动时就明确告警**，
// 由运维补配置——所以只记一次启动日志（见 StartProxyDrainWorker）。

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
	// proxyDrainFallbackLimit 是进程内补偿队列的容量上限。
	//
	// 一个用户一条（按 userID 收敛，与数据库那张表同语义）：账号数量再多，
	// 同时处于「断流意图写不进去」状态的也只会是故障期间操作过的那几个。
	// 512 足够覆盖任何真实运维场景，同时保证内存有明确上界。
	proxyDrainFallbackLimit = 512
)

// proxyDrainFallback 是一条「意图没能落库、留在内存里等数据库恢复」的记录。
type proxyDrainFallback struct {
	req proxyDrainRequest
	at  time.Time
	// attempts 是这个意图尝试落库的次数，只用于日志（不做退避：
	// 落库是轻量写，且数据库恢复的判据就是「写成功」，不需要指数退避）。
	attempts int
}

// proxyDrainFallbackQueue 是进程内补偿队列。
//
// 用 map 而不是切片：收敛语义与数据库那张表一致（一个用户一条，后来的覆盖
// 先前的）。用切片就得在每次入队时线性查找去重，账号一多就是 O(n²)。
type proxyDrainFallbackQueue struct {
	mu    sync.Mutex
	items map[uint]*proxyDrainFallback
	// dropped 统计因队列满而被丢弃的意图数（暴露给健康检查/管理页）。
	dropped atomic.Int64
	// droppedItems 保留被淘汰的**完整意图**（有界，最多 droppedRecentMax 条）。
	//
	// 只留一个数字或 ID 的话，管理员只能知道「丢过 3 条」，无法自动补偿；
	// 保留完整意图后，数据库恢复时由 flush 把它们补写回库，重新获得自动
	// 补偿机会，而不是停在一个人工处理的名单上。
	droppedItems []proxyDrainFallback
	// walPath 是整条队列（含被淘汰部分）的落盘镜像路径（空表示不落盘）。
	//
	// 进程内队列只覆盖「数据库暂时写不进去」；进程一旦重启，内存队列就没了。
	// 把完整意图落盘，重启后仍能读回来继续补写——这是「重启即丢」这条
	// 已知残余风险的兜底，也是给运维留下的人工处理清单。
	walPath string
	// walLegacyPath 是上一版只写「被淘汰意图」的旧文件路径。
	//
	// 只在 walPath 不存在时读它：升级过程中不能把上一版已经记下的清单
	// 当作不存在，否则一次升级就把已知的补偿线索丢掉了。
	walLegacyPath string
	// persisted 统计成功补写回库的意图数（说明兜底真的生效过）。
	persisted atomic.Int64
	// enqueued 统计进入队列的总数（含后来被覆盖的）。
	enqueued atomic.Int64
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

// proxyDrainWALPath 返回断流兜底队列的落盘路径。
//
// 可用 LT_PROXY_DRAIN_WAL 覆盖。默认值必须落在**持久且可写**的位置：
//
//   - 容器里根文件系统是只读的（见 deploy/docker-compose.yml 的
//     read_only: true），而 os.UserCacheDir 指向 /root/.cache 这类位置——
//     既不可写、也没挂卷。写失败后队列只剩内存，重启即丢，等于这道兜底
//     根本不存在。
//   - /data 是唯一挂出来的持久卷（面板的数据库与客户端分发包都在那儿），
//     所以优先用它。非容器部署没有 /data 时再退到缓存目录。
//
// 文件名固定而不是带实例标识：目的是让**重启后的同一实例**（通常是同一台
// 宿主机、同一份部署）能读到上次写下的清单。多实例共享同一磁盘时应通过
// LT_PROXY_DRAIN_WAL 各自指定，避免互相覆盖。
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

// dirWritable 判断目录存在且当前进程能在这里创建文件。
//
// 只查权限位不够：容器里 /data 可能挂了只读卷，权限看起来正常但 open 会
// 返回 EROFS。用一次真实的创建/删除来判定，代价是启动时一次系统调用。
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

// proxyDrainWALRecord 是 proxyDrainRequest 的可序列化镜像。
//
// proxyDrainRequest 的字段全部不导出（只在包内构造），encoding/json 看不到
// 它们，直接序列化会得到 {}。这个结构只服务于「被淘汰意图落盘」，字段与
// req 一一对应。
type proxyDrainWALRecord struct {
	// Kind 区分「仍在排队等补写」与「因队列满被淘汰」两类记录。
	//
	// 上一版只写淘汰项、没有这个字段（空值）：读到时按 dropped 处理，
	// 与旧文件语义一致。
	Kind       string             `json:"kind,omitempty"`
	UserID uint `json:"user_id"`
	// Incarnation 是意图登记时的账号标识，随记录一起落盘。
	//
	// 补偿队列的 flush 可能在重启之后：那时再从 users 表读一次「这个 ID 现在
	// 是谁」，读到的可能是复用该 ID 的新账号。用落盘的原始标识，才能保证
	// 补写出来的待办描述的是**当初那个账号**的生命周期。
	Incarnation string             `json:"incarnation,omitempty"`
	Prefix     string             `json:"prefix"`
	Gen        uint64             `json:"gen,omitempty"`
	NotAfter   time.Time          `json:"not_after,omitempty"`
	Deleted    bool               `json:"deleted,omitempty"`
	Attempts   int                `json:"attempts,omitempty"`
	Known      []proxyDrainTarget `json:"known,omitempty"`
	Intent     string             `json:"intent,omitempty"`
	NoRegister bool               `json:"no_register,omitempty"`
	At         time.Time          `json:"at"`
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
		UserID:     it.req.userID,
		Prefix:     it.req.prefix,
		Gen:        it.req.gen,
		NotAfter:   it.req.notAfter,
		Deleted:    it.req.deleted,
		Attempts:   it.req.attempts,
		Known:      it.req.known,
		Intent:     it.req.intent,
		NoRegister: it.req.noRegister,
		At:         it.at,
	}
}

// enqueue 把一条没能落库的意图放进补偿队列。
//
// 队列满时丢弃**最旧**的一条（按 at 比较）：最新的意图更接近当前真实状态，
// 而旧意图对应的账号可能已经被重新启用、甚至已经被另一条意图取代。
// 丢弃必须记指标——否则「有意图被放弃了」这件事又变成静默的。
func (q *proxyDrainFallbackQueue) enqueue(req proxyDrainRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.enqueued.Add(1)
	// 同一用户已有记录时直接覆盖：收敛语义与数据库那张表一致。
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
	q.items[req.userID] = &proxyDrainFallback{req: req, at: time.Now()}
	// 入队即落盘：正常排队的那批同样只在内存里的话，「数据库抖一下 +
	// 进程重启」就会把整批补偿线索一起带走。
	q.persistAllLocked()
}

// take 取走当前所有待补写的意图（调用方负责写库）。
//
// 取走而不是「读一份副本」：补写失败时调用方要放回去，成功则自然丢弃。
// 这样「谁在尝试」是明确的，不会出现两个协程同时补写同一条。
//
// 返回值带上入队时刻与尝试次数，让 putBack 能还原原始顺序：「丢弃最旧」
// 靠 at 判断，若放回时统一盖成当前时间，队列满时的淘汰顺序就变成随机的。
func (q *proxyDrainFallbackQueue) take() []proxyDrainFallback {
	// 这里刻意**不**重写 WAL：取走之后补写还没发生，此时把内存里的空队列
	// 落盘，等于「先把线索擦掉再尝试」，一旦补写失败或进程崩溃就彻底丢了。
	// 保持取走前的快照，最坏情况是重启后重放几条已经写成功的意图——补写是
	// 幂等 upsert，重复一次没有副作用，漏一条却是真的丢补偿。
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

// putBack 把补写失败的意图放回队列（保留原始入队时间，用于「丢弃最旧」）。
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
	// 放回同样要落盘：这一刻队列刚被补写失败重置过，WAL 必须与内存一致，
	// 否则重启后读到的是上一轮的文件——里面可能已经包含“补写成功”的项，
	// 于是同一条断流被重复登记。
	q.persistAllLocked()
}

// droppedRecentMax 是保留的「被丢弃意图」名单长度。
const droppedRecentMax = 16

// rememberDropped 保留一条因队列满被淘汰的完整意图（调用方持锁）。
// 它不再是「只留个 ID 等人工」，而是等数据库恢复后被 flush 补写回库；
// 同时立刻落盘，保证进程重启后仍能读回来。
func (q *proxyDrainFallbackQueue) rememberDropped(it proxyDrainFallback) {
	if len(q.droppedItems) >= droppedRecentMax {
		q.droppedItems = q.droppedItems[1:]
	}
	q.droppedItems = append(q.droppedItems, it)
	q.persistAllLocked()
}

// takeDropped 取走被淘汰、等待补写的意图。
//
// 只清内存、不动 WAL：补写期间若进程崩溃，WAL 里的记录仍在，重启后
// 还能继续处理。补写成功后再由 persistAll 把 WAL 收敛。
func (q *proxyDrainFallbackQueue) takeDropped() []proxyDrainFallback {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.droppedItems
	q.droppedItems = nil
	return out
}

// proxyDrainWALMaxBytes 是读取 WAL 时的字节上限。
//
// 队列上限 512 条、每条几百字节，正常文件只有一两百 KB。给 4 MiB 是为了
// 容忍异常：文件被别的东西写坏、被追加了垃圾时，读取端不能把内存读爆，
// 也不能因为一条坏行就让整个加载失败（逐行解析，坏行跳过）。
const proxyDrainWALMaxBytes = 4 << 20

// loadFromWAL 把上次进程退出前还没补写成功的意图读回内存。
//
// 只在队列构造时调用（此时尚未并发共享，不需要持锁）。
//
// 先读当前文件；当前文件没有可读内容时才退回去读上一版的文件——那一版
// 只写「被淘汰的意图」、没有 Kind 字段，读到时按 dropped 处理，与旧语义
// 一致。升级过程中不能把上一版已经记下的清单当成不存在。
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

// readWAL 逐行解析一个 WAL 文件，把记录还原进内存队列与淘汰名单。
//
// 返回值分别是读回的「排队中」与「被淘汰」条数。
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
			// 同一用户只保留一条（与内存队列的收敛语义一致）：后写的覆盖先写的，
			// 与 enqueue 的覆盖顺序相同。
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

// persistAll 把当前内存队列整体重写进 WAL（自行加锁）。
func (q *proxyDrainFallbackQueue) persistAll() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.persistAllLocked()
}

// persistAllLocked 把**整条队列**（排队中 + 被淘汰）重写进 WAL（调用方持锁）。
//
// 用「临时文件 + rename」：写一半崩溃不能留下半行 JSON，否则下次加载
// 会把整条意图解析失败并静默丢掉。整体重写而不是追加：队列最多 512 条，
// 而这个动作只发生在数据库写不进去的故障期，维护追加/截断的偏移量
// （还要处理崩溃后尾部半行）复杂得多，也更容易错。
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
			// 单条编码失败不该拖垮整份文件：跳过它，其余照写。
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

// size 返回当前队列长度（供健康检查/管理页展示）。
func (q *proxyDrainFallbackQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// ProxyDrainFallbackStats 是断流兜底队列的对外统计。
//
// 暴露成结构体而不是三个独立方法：调用方（健康检查、管理页）几乎总是要
// 一起看这三个数——只看 Queued 无法区分「一切正常」与「一直在丢」。
type ProxyDrainFallbackStats struct {
	// Queued 是当前还在等数据库恢复的意图数。
	Queued int `json:"queued"`
	// Enqueued 是累计进入队列的意图数（含后来被覆盖的）。
	Enqueued int64 `json:"enqueued"`
	// Persisted 是累计成功补写回库的意图数。
	Persisted int64 `json:"persisted"`
	// Dropped 是累计因队列满被丢弃的意图数。
	//
	// 非零意味着「有账号的残留代理失去了补偿机会」，必须人工排查。
	Dropped int64 `json:"dropped"`
	// DroppedRecent 是最近被丢弃的用户 ID（最多 16 个）。
	//
	// 有了名单，管理员可以直接按账号人工断流；只有计数的话，还得靠翻很久
	// 以前的日志去猜是谁。
	DroppedRecent []uint `json:"dropped_recent,omitempty"`
	// WALPath 是队列落盘镜像的路径（空表示不落盘）。
	//
	// 放在指标里而不是只写在文档里：兜底路径不可写时，队列**照常工作**，
	// 只有进程重启才会表现为「意图凭空消失」——那是最难归因的一类问题。
	// 运维能直接看到「落到了哪儿」，就能顺手确认它是否在持久卷上。
	WALPath string `json:"wal_path,omitempty"`
}

// ProxyDrainFallback 返回断流兜底队列的统计快照。
//
// 供健康检查与管理页展示：这个队列非空或 Dropped 非零都说明数据库曾经不可用
// 且有账号的断流意图一度只在内存里——这是需要人看一眼的状态，不能只留日志。
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

// flushProxyDrainFallback 尝试把队列里的意图全部补写回库。
//
// 定时循环已经合进 StartProxyDrainWorker（同一个 30 秒 ticker）：断流相关的
// 周期工作集中在一处，排查时不会漏看另一个协程。
//
// 补写成功后**不立刻执行断流**：意图已经进库，后台重试器
// （retryPendingProxyDrains）会按统一节奏领取并执行。在这里顺便执行一次的话，
// 同一条意图就有两个执行者，而执行本身要访问 frps（最长十几秒）——重复执行
// 既浪费又会让日志难以理解。
//
// 单次调用里「写成功一个就丢一个」：某个账号写失败不影响其它账号，
// 逐个处理比整批重试更细粒度——数据库可能只对某一行有问题（例如主键冲突）。
func (s *Services) flushProxyDrainFallback() {
	if s == nil || s.drainFallback == nil || s.DB == nil {
		return
	}
	pending := s.drainFallback.take()
	// 把此前因队列满被淘汰的意图一并捞回来尝试补写：数据库恢复后，这些
	// 本已「失去自动补偿」的账号应当重新获得补偿机会，而不是停在一个人工
	// 名单上。写不进去的会经 putBack 重新回到 droppedItems。
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
		// 还是写不进去：放回去，下一轮再试。入队时间保持原样（影响「丢弃最旧」
		// 的淘汰顺序），尝试次数 +1 只用于日志——落库是轻量写，不需要指数退避。
		s.drainFallback.putBack(it)
	}
	// 全部补写成功时内存队列已空；把 WAL 收敛成空文件，否则下次启动会把
	// 已经处理过的意图再读回来，重复登记一次断流。失败的那些已经在 putBack
	// 里写过 WAL（那时队列与文件的快照是一致的）。
	s.drainFallback.persistAll()
}
