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
// # 为什么是进程内队列，而不是再写一张表
//
// 「写一张表」在当前故障下不可行：进队列的前提就是**数据库写不进去**。
// 能做的只有把意图留在内存里，等数据库恢复后补写。代价要说清楚：
//
//   - 进程在这个窗口里重启，队列丢失——这是**已知且不可消除**的残余风险。
//     它比修改前好，是因为修改前连进程内补偿都没有；而「数据库整体不可用」
//     本身就是一次严重故障，那种状态下还会丢什么是无法完全保证的。
//   - 队列有界：数据库长时间不可用时意图会不断堆积，无界就是内存泄漏。
//     满了之后**丢弃最旧的**并记指标——最新的意图更接近当前真实状态
//     （账号可能已经被重新启用），保留它比保留一条陈旧的更有价值。
//
// # 为什么未配置 frps 不进队列
//
// 那不是「暂时失败」，而是「这个部署根本没有断流手段」。重试一万次也不会
// 成功，进队列只会让内存慢慢涨满并刷日志。它需要的是**启动时就明确告警**，
// 由运维补配置——所以只记一次启动日志（见 StartProxyDrainWorker）。

import (
	"log"
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
	// persisted 统计成功补写回库的意图数（说明兜底真的生效过）。
	persisted atomic.Int64
	// enqueued 统计进入队列的总数（含后来被覆盖的）。
	enqueued atomic.Int64
}

func newProxyDrainFallbackQueue() *proxyDrainFallbackQueue {
	return &proxyDrainFallbackQueue{items: make(map[uint]*proxyDrainFallback)}
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
}

// take 取走当前所有待补写的意图（调用方负责写库）。
//
// 取走而不是「读一份副本」：补写失败时调用方要放回去，成功则自然丢弃。
// 这样「谁在尝试」是明确的，不会出现两个协程同时补写同一条。
//
// 返回值带上入队时刻与尝试次数，让 putBack 能还原原始顺序：「丢弃最旧」
// 靠 at 判断，若放回时统一盖成当前时间，队列满时的淘汰顺序就变成随机的。
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
}

// droppedRecentMax 是保留的「被丢弃意图」名单长度。
const droppedRecentMax = 16

// rememberDropped 保留一条因队列满被淘汰的完整意图（调用方持锁）。
// 它不再是「只留个 ID 等人工」，而是等数据库恢复后被 flush 补写回库。
func (q *proxyDrainFallbackQueue) rememberDropped(it proxyDrainFallback) {
	if len(q.droppedItems) >= droppedRecentMax {
		q.droppedItems = q.droppedItems[1:]
	}
	q.droppedItems = append(q.droppedItems, it)
}

// takeDropped 取走被淘汰、等待补写的意图。
func (q *proxyDrainFallbackQueue) takeDropped() []proxyDrainFallback {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.droppedItems
	q.droppedItems = nil
	return out
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
}
