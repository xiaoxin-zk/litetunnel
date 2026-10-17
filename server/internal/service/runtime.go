package service

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// sessionInfo 一次 frpc 登录会话的缓存，避免插件回调频繁打库。
type sessionInfo struct {
	UserID   uint
	Username string
	LastSeen time.Time
}

type trafficPair struct {
	in  int64
	out int64
}

// tunnelDelta 单轮采集内某条隧道的流量增量与在线态。
type tunnelDelta struct {
	in     int64
	out    int64
	online bool
}

// Runtime 保存插件回调与流量采集共用的内存态。
//
// 之所以放在内存：frps 的 NewUserConn 回调在每次新建用户连接时都会触发，
// 这条高频路径上不允许出现数据库查询。
type Runtime struct {
	mu sync.RWMutex

	sessions map[string]sessionInfo // runID -> 会话
	exceeded map[uint]bool          // userID -> 是否超额
	online   map[uint]bool          // tunnelID -> 是否在线
	lastStat map[string]trafficPair // frp 代理全名 -> 上次采样的当日累计值
	touchAt  map[string]time.Time   // runID -> 上次会话落库时间（节流用）

	// baselineSeedPending 表示「基线表首次迁移后的第一轮采集」尚未完成。
	//
	// 只在采集协程内读写。置位由 loadTrafficBaseline 依据设置表里的迁移标记
	// 判定，清位由 collectTraffic 在基线成功落库后执行——中间任何一轮失败
	// 都保持置位，下一轮继续播种，宁可少记增量也不重复计入（两种错误方向
	// 不对称：少记一轮最多丢两分钟的账，重复计入是实打实的双倍扣费）。
	baselineSeedPending bool

	// pendingTrafficReset 登记了「管理员刚清零用量」的用户。
	//
	// 为什么需要它：清零写的是绝对值（traffic_used = 0），采集写的是增量。
	// 清零后紧邻一轮的增量是清零**之前**采样的旧流量，照常加回去等于
	// 「清零完又冒出来」。清零操作在这里登记；flushTraffic 落增量前对
	// 标记做快照，并在**同一事务**里跳过这些用户——清零时刻之前的增量
	// 全部丢弃，边界明确。标记先于清零写库登记，因此任何在清零提交后
	// 落库的增量都会被至少一轮的跳过覆盖住。
	//
	// 值是**登记代次**（resetSeq 单调递增），而不是布尔值。快照（取走）
	// 不再把标记从 map 里摘掉：摘掉的话，登记方随后撤销（清零写库失败）
	// 就只能删到「还没被取走」的标记，采集器手里的旧快照照样按它跳过
	// ——一次失败的清零仍会丢弃一轮真实用量。现在的做法是快照只读副本，
	// 事务成功后按代次摘除（consumePendingTrafficResets），失败则原样
	// 留在 map 里等下一轮，天然不需要「归还」。
	//
	// 撤销（UnmarkTrafficResetPending）记录作废代次（resetVoid）：代次
	// 不大于它的快照一律失效——无论标记还在 map 里、还是已在某次快照
	// 中，都无法再造成跳过。
	pendingTrafficReset map[uint]uint64

	// resetSeq 是清零登记的单调代次；resetVoid 记录每个用户最后一次
	// 撤销时的代次，代次 ≤ 它的快照跳过一律无效（见 pendingTrafficReset）。
	resetSeq       uint64
	resetVoidUntil map[uint]uint64

	// guardVer 是准入标记（超额/禁用）的版本号。
	//
	// 后台配额刷新按「读库快照 → 逐个写标记」两步走，两步之间管理员的
	// 改动（调低配额并置超额）可能被旧快照覆盖掉；而插件热路径只认内存，
	// 若后续采集恰好持续失败，错误状态会一直保留。任何管理路径写标记前
	// 都递增版本号（BumpGuardVer），刷新以「读库前取的版本号」做条件写
	// （SetGuardFlagsIfVer）：版本变了就整轮让路，下一轮快照自然是最新的。
	guardVer uint64

	// blocked 记录「账号被禁用/封禁」。
	//
	// 必须与 exceeded **分开存**：exceeded 是「流量用超了」，会被每次流量
	// 采集按配额重算；而账号是否可用只由管理员的状态设置决定。
	// 以前禁用是靠把 exceeded 强制置 true 实现的，于是配额没超限的禁用用户
	// 会在下一次成功采集后被重新放行——禁用形同虚设，而且完全取决于
	// 采集是否跑过，现象随机。
	blocked map[uint]bool

	// guardReady 表示「超额与禁用标记」是否已经成功从数据库加载过至少一次。
	//
	// 为什么需要一个显式的就绪位：这两个标记只由流量采集维护，而采集会在
	// 数据库不可用、采样基线读不出来、frps 管理 API 不可达时**整轮跳过**
	// （这是有意的，见 collectTraffic）。跳过时内存里就是「谁都没超额、
	// 谁都没被禁用」，而插件热路径把「查不到」当成「没超额」放行——
	// 控制面刚启动、第一次采集还没跑成的那段时间里，超额用户与已禁用账号
	// 重连都能照常建隧道，而那一刻恰恰是所有客户端都在重连的时候。
	//
	// 所以把「状态未知」变成一个可查询的事实，由插件显式拒绝（fail-closed）。
	guardReady bool

	identities map[identityKey]identityState // 账号有效性短缓存
}

// 账号有效性缓存的命名空间。
const (
	IdentityKindUser  uint8 = 1
	IdentityKindAdmin uint8 = 2
)

// identityTTL 是账号有效性缓存的存活时间。
//
// 每次请求都查库能保证「禁用立即生效」，但 SQLite 单写者模型下会成为瓶颈。
// 10 秒的窗口在安全性与吞吐之间取得平衡：账号被禁用后最多 10 秒令牌失效，
// 同时把每请求一次查询降为每个账号每 10 秒一次。
const identityTTL = 10 * time.Second

type identityKey struct {
	kind uint8
	id   uint
}

// identityState 缓存账号的有效性与令牌版本，供每次请求快速校验。
type identityState struct {
	active  bool
	version int
	at      time.Time
}

// NewRuntime 构造内存态。
func NewRuntime() *Runtime {
	return &Runtime{
		sessions:   make(map[string]sessionInfo),
		exceeded:   make(map[uint]bool),
		blocked:    make(map[uint]bool),
		online:     make(map[uint]bool),
		lastStat:   make(map[string]trafficPair),
		touchAt:    make(map[string]time.Time),
		identities: make(map[identityKey]identityState),
	}
}

// CachedIdentity 读取账号状态缓存，返回 (是否有效, 令牌版本, 是否命中)。
func (r *Runtime) CachedIdentity(kind uint8, id uint) (bool, int, bool) {
	key := identityKey{kind: kind, id: id}
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.identities[key]
	if !ok || time.Since(st.at) > identityTTL {
		return false, 0, false
	}
	return st.active, st.version, true
}

// SetCachedIdentity 写入账号状态缓存。
func (r *Runtime) SetCachedIdentity(kind uint8, id uint, active bool, version int) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[key] = identityState{active: active, version: version, at: time.Now()}
}

// InvalidateIdentity 立即失效某个账号的缓存。
// 禁用 / 删除账号时必须调用，否则最长会有 identityTTL 的生效延迟。
func (r *Runtime) InvalidateIdentity(kind uint8, id uint) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.identities, key)
}

// ShouldTouch 判断某会话是否已达到落库节流间隔。
// frpc 的心跳默认 30 秒一次，若每次都写库会造成无谓的写放大。
func (r *Runtime) ShouldTouch(runID string, interval time.Duration) bool {
	if runID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.touchAt[runID]
	if ok && time.Since(last) < interval {
		return false
	}
	r.touchAt[runID] = time.Now()
	return true
}

// TouchClientSession 以节流方式刷新客户端会话的在线时间。
//
// # 心跳只能续期，不能复活
//
// 更新条件里必须带 online = true。以前是无条件写回 online = true，
// 于是有一条很隐蔽的提权路径：
//
//	凭据轮换 / 重置密码 → 会话被置为离线、内存会话被清掉
//	→ 旧 frpc 继续心跳 → 会话又被改回在线（last_seen_at 也刷新了）
//	→ 下一次 NewProxy / NewUserConn 走 FindTrustedClientSession 命中
//	  这条「在线且刚更新」的记录，于是**跳过新凭据校验**被放行。
//
// 会话重新变为在线只能通过一条路：新的 Login，或凭据复核通过后的补登记
// （UpsertClientSession）——它们都会先验过当前生效的凭据。
func (s *Services) TouchClientSession(runID string) {
	if !s.Runtime.ShouldTouch(runID, time.Minute) {
		return
	}
	res := s.DB.Model(&model.ClientSession{}).
		Where("run_id = ? AND online = ?", runID, true).
		Update("last_seen_at", time.Now())
	if res.Error != nil {
		log.Printf("[session] 刷新会话心跳失败（run_id=%s）: %v", runID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		// 没有命中在线会话：要么会话已被撤销（凭据轮换、改密、删号），
		// 要么它从来就不存在。两种情况下心跳都不该产生任何效果，
		// 但值得记一条日志——这是「旧凭据还在试图续期」的信号。
		log.Printf("[session] 心跳未命中在线会话（run_id=%s，可能已被撤销），已忽略", runID)
	}
}

// sessionTrustWindow 是数据库会话被视为可信的最长时间。
// 超过该窗口说明客户端已长时间无心跳，必须重新完成凭据校验。
const sessionTrustWindow = 10 * time.Minute

// FindTrustedClientSession 按 runID 查找一个「确实完成过认证」的会话。
//
// 这是服务端插件在内存缓存未命中时的唯一回落依据：
// 会话表只在 Login 通过每用户凭据校验后写入，因此这里的结果可以信任。
func (s *Services) FindTrustedClientSession(runID string) (*model.ClientSession, error) {
	if runID == "" {
		return nil, ErrNotFound
	}
	var sess model.ClientSession
	err := s.DB.Where("run_id = ? AND online = ?", runID, true).First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Since(sess.LastSeenAt) > sessionTrustWindow {
		return nil, ErrNotFound
	}
	return &sess, nil
}

// MarkStaleSessionsOffline 把长时间未上报心跳的会话标记为离线。
func (s *Services) MarkStaleSessionsOffline(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	_ = s.DB.Model(&model.ClientSession{}).
		Where("online = ? AND last_seen_at < ?", true, cutoff).
		Update("online", false).Error
}

// RecordLogin 记录一次成功登录。
func (r *Runtime) RecordLogin(runID string, userID uint, username string) {
	if runID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[runID] = sessionInfo{UserID: userID, Username: username, LastSeen: time.Now()}
}

// LookupSession 按 runID 查会话。
func (r *Runtime) LookupSession(runID string) (sessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[runID]
	return s, ok
}

// TouchSession 刷新会话活跃时间。
func (r *Runtime) TouchSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.LastSeen = time.Now()
		r.sessions[runID] = s
	}
}

// DropSession 注销会话。
func (r *Runtime) DropSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, runID)
	// 节流记录一并清掉：它只为「这个 runID 还活着」服务，
	// 会话没了就没有保留价值，留着只会随客户端重连越积越多。
	delete(r.touchAt, runID)
}

// DropUserSessions 注销某用户的全部会话，返回清理掉的条数。
//
// 用途：凭据被轮换、密码被重置、账号被删除时，已经登录的 frpc 必须立刻
// 失去放行资格。只清数据库会话是不够的——插件热路径（onNewUserConn，
// 每次新建用户连接都经过）先查内存会话，命中后只看配额就放行，
// 根本不会去读数据库。于是「已吊销」的客户端还能继续接受新连接。
func (r *Runtime) DropUserSessions(userID uint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for runID, s := range r.sessions {
		if s.UserID == userID {
			delete(r.sessions, runID)
			delete(r.touchAt, runID)
			n++
		}
	}
	return n
}

// AccessGuardReady 报告准入状态（超额与禁用标记）是否已加载完成。
//
// 返回 false 时内存里的两个标记都不可信，调用方必须按「不该放行」处理：
// 此时「查不到」与「没超额」在数据结构上完全一样，放行等于关掉准入控制。
func (r *Runtime) AccessGuardReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.guardReady
}

// markAccessGuardReady 在整表加载成功后置位。
//
// 只在成功时置位、失败时不撤销：拿过一份完整快照之后，「已知但可能略旧」
// 仍然比「未知」可信——未知会被当成「没超额」而放行。
func (r *Runtime) markAccessGuardReady() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guardReady = true
}

// IsQuotaExceeded 查询用户是否超额。
func (r *Runtime) IsQuotaExceeded(userID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.exceeded[userID]
}

// SetQuotaExceeded 写入超额状态。
func (r *Runtime) SetQuotaExceeded(userID uint, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
}

// SetQuotaExceededIfVer 按版本号条件写入超额标记（只动超额，不碰禁用）。
//
// 管理侧的配额刷新同样存在「读库 → 算超额 → 写标记」的窗口：两个并发的
// 配额调整，先发起的那笔可能读到旧配额、后完成，用旧结果覆盖新标记。
// 版本号在**读库之前**取，写入时代次不一致就放弃，由调用方重读重试——
// 与后台整表刷新用的是同一套协调机制。
func (r *Runtime) SetQuotaExceededIfVer(userID uint, v bool, ver uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guardVer != ver {
		return false
	}
	if v {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
	return true
}

// MarkTrafficResetPending 登记一次用量清零（见 pendingTrafficReset），
// 返回本次登记的**代次**。
//
// 代次必须由登记方持有并原样传给撤销：同一用户可能有多笔并发清零，
// 按用户整体撤销会把别人刚登记成功的标记一并作废——那一笔的旧增量
// 随后就会被加回（「清零完又冒出来」）。按代次撤销只作废自己那一笔。
func (r *Runtime) MarkTrafficResetPending(userID uint) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetSeq++
	if r.pendingTrafficReset == nil {
		r.pendingTrafficReset = map[uint]uint64{}
	}
	r.pendingTrafficReset[userID] = r.resetSeq
	return r.resetSeq
}

// takePendingTrafficResets 给清零标记做快照，供 flushTraffic 在事务里
// 决定跳过谁。
//
// 快照**不摘除**标记：摘除的话，事务失败时标记已经不在 map 里，
// 而登记方随后的撤销（清零写库失败）也拦不住手里的旧快照——两条失败
// 路径都会漏。现在标记留在原处：事务成功后由 consumePendingTrafficResets
// 按代次摘除，失败则原样等待下一轮。
func (r *Runtime) takePendingTrafficResets() map[uint]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pendingTrafficReset) == 0 {
		return nil
	}
	out := make(map[uint]uint64, len(r.pendingTrafficReset))
	for uid, gen := range r.pendingTrafficReset {
		out[uid] = gen
	}
	return out
}

// resetSkipValid 判断快照里某用户的跳过是否仍然有效：撤销（清零写库失败）
// 会推进该用户的作废代次，代次不超过它的快照一律失效——否则一次失败的
// 清零会让采集器丢弃一轮真实用量。
func (r *Runtime) resetSkipValid(userID uint, gen uint64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return gen > r.resetVoidUntil[userID]
}

// consumePendingTrafficResets 在采集事务**成功提交**后摘除已消费的标记。
// 期间被重新登记的用户（代次已推进）保留新标记，由下一轮继续跳过。
func (r *Runtime) consumePendingTrafficResets(taken map[uint]uint64) {
	if len(taken) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for uid, gen := range taken {
		if r.pendingTrafficReset[uid] == gen {
			delete(r.pendingTrafficReset, uid)
		}
	}
}

// UnmarkTrafficResetPending 撤销**指定代次**的登记：清零写库失败时由
// 登记方调用，避免后续采集错误丢弃一轮真实用量。
//
// 只作用于自己那一笔：同一用户可能还有别人登记成功的更新代次，
// 按用户整体删除会把它们一起作废。作废边界取该代次本身而不是新的
// 全局代次——快照里代次 ≤ 本代次的跳过失效，更大的（并发的成功登记）
// 依然有效。
func (r *Runtime) UnmarkTrafficResetPending(userID uint, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resetVoidUntil == nil {
		r.resetVoidUntil = map[uint]uint64{}
	}
	if r.resetVoidUntil[userID] < gen {
		r.resetVoidUntil[userID] = gen
	}
	if cur, ok := r.pendingTrafficReset[userID]; ok && cur == gen {
		delete(r.pendingTrafficReset, userID)
	}
}

// BumpGuardVer 递增准入标记版本号：管理路径写标记前必须调用，
// 让在途的后台刷新识别「快照已过时」并让路。
func (r *Runtime) BumpGuardVer() {
	r.mu.Lock()
	r.guardVer++
	r.mu.Unlock()
}

// GuardVer 取当前版本号。刷新流程在**读库之前**取，
// 之后用 SetGuardFlagsIfVer 条件写。
func (r *Runtime) GuardVer() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.guardVer
}

// SetGuardFlagsIfVer 按版本号条件写入超额与禁用标记。
// 版本已变化（返回 false）时什么都不写：内存里是管理员刚写的权威值，
// 旧快照不得覆盖。
func (r *Runtime) SetGuardFlagsIfVer(userID uint, exceeded, blocked bool, ver uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guardVer != ver {
		return false
	}
	if exceeded {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
	if blocked {
		r.blocked[userID] = true
	} else {
		delete(r.blocked, userID)
	}
	return true
}

// IsUserBlocked 查询账号是否被禁用/封禁。
func (r *Runtime) IsUserBlocked(userID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.blocked[userID]
}

// SetUserBlocked 写入「账号不可用」状态。
//
// 与 SetQuotaExceeded 分开：这个值只由管理员的状态设置与账号状态同步决定，
// 不会被流量采集重算，因此禁用之后不会因为一次成功采集而被悄悄解除。
func (r *Runtime) SetUserBlocked(userID uint, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v {
		r.blocked[userID] = true
	} else {
		delete(r.blocked, userID)
	}
}

// IsTunnelOnline 查询隧道在线态。
func (r *Runtime) IsTunnelOnline(tunnelID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.online[tunnelID]
}

func (r *Runtime) setOnlineTunnels(m map[uint]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.online = m
}

// GC 清理长时间无心跳的会话。
func (r *Runtime) GC(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.sessions {
		if v.LastSeen.Before(cutoff) {
			delete(r.sessions, k)
			delete(r.touchAt, k)
		}
	}
	// 还有一类节流记录没有对应会话：心跳对「库里存在、内存里没有」的
	// runID 同样生效（重启后就是这样），它们只能按时间清。
	// 不按时间清的话，客户端反复重连会让这张表只增不减。
	for k, at := range r.touchAt {
		if at.Before(cutoff) {
			delete(r.touchAt, k)
		}
	}
}

// StartTrafficCollector 启动后台采集协程，直到 ctx 结束。
func (s *Services) StartTrafficCollector(ctx context.Context) {
	interval := s.Cfg.TrafficPollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		gcTicker := time.NewTicker(10 * time.Minute)
		defer gcTicker.Stop()

		// 先把当天的采样基线读回来，再跑第一次采集。
		//
		// 顺序不能反：第一次采集如果先跑，就会拿空基线去算增量，把 frps 的
		// 当天累计值整个记成新增量（用户配额被凭空扣掉一大截）。
		//
		// 读失败时**必须跳过采集**，而不是「读不到就当空基线」：空基线的效果
		// 与「没有基线」完全一样——当天累计值会被整个记成新增量，正是这条
		// 逻辑要防的事。数据库读失败通常是瞬时的，等下一轮重试即可。
		// 准入状态再兜一次，并且**与采集解耦**。
		//
		// main.go 在开始监听之前已经同步加载过一次，但那一次可能恰好撞上
		// 数据库不可用。此后如果只在「采集成功」时才刷新它，那么 frps 管理
		// API 一挂，配额判断就永远停在「未知」——按 fail-closed 会拒绝所有人，
		// 而这本来只是 frps 的问题，与谁超额无关。
		guardReady := s.LoadAccessGuard()

		baselineReady := s.loadTrafficBaseline()
		if baselineReady {
			// 启动即跑一次，避免控制台首屏空白。
			s.collectTraffic(ctx)
		} else {
			log.Printf("[traffic] 采样基线尚未就绪，本轮跳过采集（下个周期重试）")
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !guardReady {
					// 与基线一样只在恢复时打一行：数据库长时间不可用时，
					// 每轮都打只会把日志刷满。
					if guardReady = s.LoadAccessGuard(); guardReady {
						log.Printf("[quota] 准入状态已就绪，恢复按配额与账号状态拦截")
					}
				}
				if !baselineReady {
					// 只在恢复时打一行：数据库长时间不可用时，每轮都打
					// 只会把日志刷满，而结论一直是同一个。
					if baselineReady = s.loadTrafficBaseline(); !baselineReady {
						continue
					}
					log.Printf("[traffic] 采样基线已恢复，继续采集")
				}
				s.collectTraffic(ctx)
			case <-gcTicker.C:
				s.Runtime.GC(15 * time.Minute)
				s.MarkStaleSessionsOffline(5 * time.Minute)
			}
		}
	}()
}

// collectTraffic 单次采集：拉取 frps 代理状态，计算增量并落库。
func (s *Services) collectTraffic(ctx context.Context) {
	proxies, err := s.Frps.ListProxies(ctx)
	if err != nil {
		// 采集失败不致命：frps 可能正在重启，下一轮会自动恢复。
		//
		// 但**必须在这里就返回**：下面会把本轮的在线集合整体替换掉，
		// 拿不到可信数据却照常替换，等于把所有隧道一次性判成离线——
		// 客户端集体显示「连接中」，而真实原因只是采集出了问题。
		// 保留上一次的在线状态，直到拿到可信结果为止。
		log.Printf("[traffic] 拉取 frps 代理状态失败（保留上次在线状态）: %v", err)
		return
	}

	// 一次性载入映射表。单机部署下规模有限，用内存换掉 N+1 查询。
	var users []model.User
	if err := s.DB.Find(&users).Error; err != nil {
		log.Printf("[traffic] 载入用户失败: %v", err)
		return
	}
	userByID := make(map[uint]*model.User, len(users))
	for i := range users {
		userByID[users[i].ID] = &users[i]
	}

	var tunnels []model.Tunnel
	if err := s.DB.Find(&tunnels).Error; err != nil {
		log.Printf("[traffic] 载入隧道失败: %v", err)
		return
	}
	// 用不可变的用户 ID 建索引：frp 的 user 字段是 lt_u<id>，与用户名无关。
	type tunnelKey struct {
		userID uint
		tunnel string
	}
	tunnelByKey := make(map[tunnelKey]*model.Tunnel, len(tunnels))
	tunnelOwner := make(map[uint]uint, len(tunnels))
	for i := range tunnels {
		tunnelByKey[tunnelKey{userID: tunnels[i].UserID, tunnel: tunnels[i].Name}] = &tunnels[i]
		tunnelOwner[tunnels[i].ID] = tunnels[i].UserID
	}

	tunnelDeltas := make(map[uint]*tunnelDelta, len(tunnels))
	userDeltas := make(map[uint]int64)
	onlineNow := make(map[uint]bool, len(tunnels))

	s.Runtime.mu.Lock()
	lastStat := s.Runtime.lastStat
	// 本轮的新基线先攒在一边，落库成功之后再提交。
	//
	// 曾经是直接改 lastStat：事务失败时基线已经被推进了，那一轮的增量
	// 就**永久丢失**——下一轮从新基线算增量，中间这段流量再也不会被记上。
	// 用户看到的已用量比实际少（等于配额被悄悄放宽），统计也缺一块，
	// 而且没有任何地方报错。
	//
	// 攒在一边之后，失败只是「这一轮不提交」：下一轮仍用旧基线算增量，
	// 期间的流量会在下次成功时一起补记。
	nextStat := make(map[string]trafficPair, len(proxies))
	for _, p := range proxies {
		frpUser, tunnelName, ok := ParseProxyName(p.Name)
		if !ok {
			continue
		}
		userID, ok := UserIDFromFrpUser(frpUser)
		if !ok {
			continue
		}
		u, ok := userByID[userID]
		if !ok {
			continue
		}
		t, ok := tunnelByKey[tunnelKey{userID: userID, tunnel: tunnelName}]
		if !ok {
			continue
		}

		cur := trafficPair{in: p.Status.TodayTrafficIn, out: p.Status.TodayTrafficOut}
		prev := lastStat[p.Name]
		din, dout := cur.in-prev.in, cur.out-prev.out
		// frps 的当日统计跨零点归零，此时当前值本身就是增量。
		if din < 0 {
			din = cur.in
		}
		if dout < 0 {
			dout = cur.out
		}
		nextStat[p.Name] = cur

		d := tunnelDeltas[t.ID]
		if d == nil {
			d = &tunnelDelta{}
			tunnelDeltas[t.ID] = d
		}
		d.in += din
		d.out += dout
		running := IsProxyOnline(p.Status.Phase)
		d.online = d.online || running
		if running {
			onlineNow[t.ID] = true
		}
		userDeltas[u.ID] += din + dout
	}
	// 未匹配到隧道的代理不进新基线，等于顺手清掉了历史残留，
	// 防止内存随历史代理无限增长。
	s.Runtime.mu.Unlock()

	s.Runtime.setOnlineTunnels(onlineNow)

	s.Runtime.mu.Lock()
	seedBaseline := s.Runtime.baselineSeedPending
	s.Runtime.mu.Unlock()

	if err := s.flushTraffic(tunnelDeltas, userDeltas, tunnelOwner, nextStat, seedBaseline); err != nil {
		log.Printf("[traffic] 流量落库失败，本轮不推进采样基线（增量下轮补记）: %v", err)
	} else {
		s.Runtime.mu.Lock()
		s.Runtime.lastStat = nextStat
		s.Runtime.baselineSeedPending = false
		s.Runtime.mu.Unlock()
		if seedBaseline {
			// 首次迁移的基线写成功了，落下迁移标记。
			// 两步之间若崩溃，下次启动仍按首次迁移处理：再跳过一轮增量。
			// 代价是极小窗口内少记两分钟流量，方向仍然安全。
			if err := s.Settings.SetInternal(map[SettingKey]string{KeyTrafficBaselineReady: "1"}); err != nil {
				log.Printf("[traffic] 写入基线迁移标记失败（下轮仍按首次迁移处理）: %v", err)
			} else {
				log.Printf("[traffic] 首次基线已建立，后续采集恢复正常计增量")
			}
		}
	}
	// 配额标记无论落库成败都要重算：它读的是库里**已有**的用量，
	// 与这一次写入是否成功无关。跳过它只会让超额状态更久不收敛。
	s.refreshQuotaFlags()
}

// flushTraffic 将本轮增量与采样基线一并写库。
//
// 返回错误而不是只记日志：调用方要靠它决定**要不要推进内存里的采样基线**。
// 失败时推进基线等于把这一轮的流量永久丢掉。
//
// nextStat 是本轮采样到的新基线，必须与增量在同一个事务里提交：
//
//   - 增量记上了、基线没推进 → 下一轮会把同一批流量再算一遍（重复计入）；
//   - 基线推进了、增量没记上 → 这批流量永久漏记。
//
// 两种失真都会直接影响用户配额，且事后很难发现，所以它们必须同生共死。
//
// seed 为 true 时只写基线、跳过全部增量写入：这是基线表首次迁移后的
// 第一轮采集，frps 的当天累计值是旧版本已经计过的，从零起算会把当天
// 已计流量整个重复计入（见 loadTrafficBaseline 的迁移标记说明）。
func (s *Services) flushTraffic(
	tunnelDeltas map[uint]*tunnelDelta,
	userDeltas map[uint]int64,
	tunnelOwner map[uint]uint,
	nextStat map[string]trafficPair,
	seed bool,
) error {
	now := time.Now()
	today := now.Format("2006-01-02")

	// 在事务**外**对清零标记做快照：快照只读不摘，事务失败时标记原样
	// 留在 map 里等下一轮；事务成功后按代次摘除已消费的标记。
	// （旧实现是「取走即消费、失败再归还」，但归还拦不住登记方紧随其后的
	// 撤销——一次失败的清零仍会让采集器丢一轮真实用量。）
	skipUsers := s.Runtime.takePendingTrafficResets()

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !seed {
			for id, d := range tunnelDeltas {
				total := d.in + d.out
				if total == 0 && !d.online {
					continue
				}
				updates := map[string]any{}
				if total > 0 {
					updates["traffic_used"] = gorm.Expr("traffic_used + ?", total)
				}
				if d.online {
					updates["last_online_at"] = now
				}
				if len(updates) == 0 {
					continue
				}
				if err := tx.Model(&model.Tunnel{}).Where("id = ?", id).Updates(updates).Error; err != nil {
					return err
				}
			}

			// 管理员清零与采集增量的协调（见 pendingTrafficReset）：
			// 清零后紧邻一轮的增量是清零前采样的旧流量，加回去等于
			// 「清零完又冒出来」。标记已在事务外做快照（skipUsers），
			// 这里按**仍然有效**的跳过——清零时刻之前的增量全部丢弃。
			// 登记方撤销（清零写库失败）后快照即刻失效，真实用量照常入账。
			// 隧道级统计照常累加：清零的是用户的周期用量，
			// 隧道的累计与日明细不受影响。
			for uid, delta := range userDeltas {
				if delta <= 0 {
					continue
				}
				if gen, ok := skipUsers[uid]; ok && s.Runtime.resetSkipValid(uid, gen) {
					continue
				}
				if err := tx.Model(&model.User{}).Where("id = ?", uid).
					Update("traffic_used", gorm.Expr("traffic_used + ?", delta)).Error; err != nil {
					return err
				}
			}

			for id, d := range tunnelDeltas {
				if d.in == 0 && d.out == 0 {
					continue
				}
				uid, ok := tunnelOwner[id]
				if !ok {
					continue
				}
				row := model.TrafficDaily{
					UserID:   uid,
					TunnelID: id,
					Date:     today,
					InBytes:  d.in,
					OutBytes: d.out,
				}
				// 唯一键 (user_id, tunnel_id, date) 上做累加 upsert。
				if err := tx.Clauses(clause.OnConflict{
					Columns: []clause.Column{{Name: "user_id"}, {Name: "tunnel_id"}, {Name: "date"}},
					DoUpdates: clause.Assignments(map[string]any{
						"in_bytes":  gorm.Expr("lt_traffic_daily.in_bytes + ?", d.in),
						"out_bytes": gorm.Expr("lt_traffic_daily.out_bytes + ?", d.out),
					}),
				}).Create(&row).Error; err != nil {
					return err
				}
			}
		}

		// ---- 采样基线 ----
		//
		// 昨天的基线直接删掉：frps 的当日累计值跨零点归零，拿昨天的基线
		// 相减会得到负数（调用方会把负数当「当天全部流量」处理，等于把
		// 新一天的流量重复算一遍）。
		if err := tx.Where("date <> ?", today).Delete(&model.TrafficBaseline{}).Error; err != nil {
			return err
		}

		names := make([]string, 0, len(nextStat))
		for name, cur := range nextStat {
			names = append(names, name)
			row := model.TrafficBaseline{
				ProxyName: name,
				Date:      today,
				InBytes:   cur.in,
				OutBytes:  cur.out,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "proxy_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"date", "in_bytes", "out_bytes"}),
			}).Create(&row).Error; err != nil {
				return err
			}
		}
		// 已经消失的代理要把基线删掉，否则这张表会随历史代理一直长。
		if len(names) == 0 {
			if err := tx.Where("1 = 1").Delete(&model.TrafficBaseline{}).Error; err != nil {
				return err
			}
		} else if err := tx.Where("proxy_name NOT IN ?", names).
			Delete(&model.TrafficBaseline{}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		// 事务失败（含提交失败）：基线还停在旧值，标记原样留在 map 里，
		// 下一轮继续按它跳过——「清零完又冒出来」正是要防的。
		return err
	}
	// 成功提交：本轮快照消费完毕。期间被重新登记的用户代次已推进，
	// consume 只摘除代次未变的，新标记留给下一轮。
	s.Runtime.consumePendingTrafficResets(skipUsers)
	return nil
}

// loadTrafficBaseline 把当天的采样基线读回内存。返回是否读取成功。
//
// 不恢复的话，控制面重启后第一次采集会把 frps 的**当天累计值**整个当成
// 新增量记一遍——用户配额被凭空扣掉一大截，统计翻倍。这只在「只重启控制面、
// frps 没重启」时出现，而滚动升级恰好就是这个形态。
//
// 返回值必须被调用方当回事：读失败时不能「当作空基线继续跑」——那与没有基线
// 是同一件事，照样会把当天累计值重复记一遍。正确做法是跳过这一轮采集，
// 等下个周期重试。
func (s *Services) loadTrafficBaseline() bool {
	// 首次迁移判定放在读基线之前。基线表的「空」有两种含义：
	//
	//   a) 首次迁移 / 全新部署：从没写过任何基线；
	//   b) 当天还没有采集轮次写入：正常状态。
	//
	// 不区分的话，升级旧库后的第一轮采集会把 frps 的当天累计值从零起算
	// 整个计入——而那部分流量旧版本已经计过，用户被重复扣费，甚至触发
	// 超额封禁。用设置表里的迁移标记区分：缺失即首次迁移，第一轮只写
	// 基线、不计增量（见 collectTraffic 与 flushTraffic）。
	//
	// 读标记失败按「需要播种」处理：宁可少记一轮增量，也不能重复计入
	// ——两种错误方向不对称。
	seed := !s.Settings.Bool(KeyTrafficBaselineReady)

	today := time.Now().Format("2006-01-02")
	var rows []model.TrafficBaseline
	if err := s.DB.Where("date = ?", today).Find(&rows).Error; err != nil {
		log.Printf("[traffic] 读取采样基线失败，将跳过采集以避免重复计入当天流量: %v", err)
		return false
	}

	m := make(map[string]trafficPair, len(rows))
	for _, r := range rows {
		m[r.ProxyName] = trafficPair{in: r.InBytes, out: r.OutBytes}
	}

	s.Runtime.mu.Lock()
	s.Runtime.lastStat = m
	s.Runtime.baselineSeedPending = seed
	s.Runtime.mu.Unlock()

	if len(m) > 0 {
		log.Printf("[traffic] 已恢复 %d 条采样基线（避免重启后重复计入当天流量）", len(m))
	}
	if seed {
		log.Printf("[traffic] 未发现基线迁移标记，第一轮采集只记录基线、不计流量增量")
	}
	return true
}

// refreshQuotaFlags 刷新内存中的超额与禁用标记，供 frps 插件实时拦截。
//
// 两个标记一起同步，因为它们来源不同、用途也不同：
//
//   - 超额：由用量与配额算出来（会随流量变化）；
//   - 禁用：由账号状态决定（只随管理员操作变化）。
//
// 放在这里同步「禁用」是为了覆盖重启：进程重启后内存是空的，而插件热路径
// 只查内存，不在这里补齐的话，已禁用的账号在重启后会重新被放行，
// 直到管理员再动一次那个账号。
func (s *Services) refreshQuotaFlags() error {
	// 整轮必须在**版本稳定**的前提下完成：版本号在读库之前取，期间管理员的
	// 改动（BumpGuardVer）会让剩余的条件写全部让路——那部分用户的标记就
	// 没刷到，此时绝不能宣告就绪（guardReady），否则插件会按「内存完整」
	// 放行实际上没有标记的账号。检测到版本变化就换新版本号整轮重试，
	// 有限次后放弃（不标记就绪，插件继续 fail-closed，下一轮采集再来）。
	const maxPasses = 3
	for pass := 0; ; pass++ {
		ver := s.Runtime.GuardVer()
		var users []model.User
		if err := s.DB.Preload("Group").Find(&users).Error; err != nil {
			log.Printf("[quota] 刷新超额标记失败: %v", err)
			return err
		}
		for i := range users {
			s.EnsureTrafficPeriod(&users[i])
			// 快照期间该用户被管理员动过：跳过，内存里保留管理员写的权威值。
			s.Runtime.SetGuardFlagsIfVer(users[i].ID,
				s.QuotaExceeded(&users[i]),
				users[i].Status != model.UserStatusActive,
				ver)
		}
		if s.Runtime.GuardVer() == ver {
			// 版本全程未变：所有条件写都生效了，整表完整，才能宣告就绪。
			s.Runtime.markAccessGuardReady()
			return nil
		}
		if pass+1 >= maxPasses {
			log.Printf("[quota] 配额标记刷新连续 %d 轮被管理操作打断，本轮不宣告就绪（下一轮采集重试）", maxPasses)
			return nil
		}
	}
}

// LoadAccessGuard 从数据库加载准入状态（超额与禁用标记），返回是否成功。
//
// 必须在开始接受请求**之前**同步调用一次（见 cmd/panel/main.go）：插件热路径
// 只查内存，而这两个标记只由它维护。少了这一步，控制面从启动到第一次成功
// 采集之间的窗口里，「内存里什么都没有」会被当成「谁都没超额」，超额用户与
// 已禁用账号照样能建隧道——而重启后所有客户端都在重连，正是准入控制最该
// 生效的时刻。
//
// 失败时不阻断启动：准入状态保持「未知」，插件会显式拒绝（fail-closed），
// 采集协程持续重试直到数据库恢复。
func (s *Services) LoadAccessGuard() bool {
	if err := s.refreshQuotaFlags(); err != nil {
		log.Printf("[quota] 加载准入状态失败，在成功加载前将拒绝新建隧道: %v", err)
		return false
	}
	// 返回「是否真正就绪」而不是「是否没有报错」：刷新可能被管理操作
	// 打断而不完整（未标记 guardReady）。返回 false 让采集协程下一轮
	// 重试，插件侧在这之前继续按「状态未知」拒绝——宁可慢一轮，
	// 也不能让不完整的标记冒充完整。
	return s.Runtime.AccessGuardReady()
}
