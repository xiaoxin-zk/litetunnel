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

// sameDay 判断两个时刻是否落在同一天（服务端本地时区，与哨兵 key 的
// 「今天」口径一致）。
//
// 用在「旧基线是否还能用」的判断上：frps 的当日累计值跨零点归零，
// 跨天的旧基线相减会得到负数——调用方把负数当「当天全部流量」处理，
// 等于把新一天的流量又记一遍。
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

type trafficPair struct {
	in  int64
	out int64
	// seenAt 是这个名字最后一次出现在 frps 列表里的时刻。
	//
	// 只用于「本轮没出现的代理要不要保留基线」，不参与增量计算：
	// 代理因为客户端重连、或分页期间的一删一增而短暂缺席时，若把基线丢掉，
	// 它下次出现会被当成「此前从未见过」，当天的累计值会被整个再记一遍。
	seenAt time.Time
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

	// resetMu 串行化「采集按清零标记跳过并提交」与「登记方撤销」。
	//
	// 光靠代次比较还不够：flushTraffic 在事务里校验代次有效之后、提交之前，
	// 清零那笔的写库可能失败并撤销——撤销抹不掉已经做出的跳过决定，
	// 这一轮的真实增量仍然被丢掉。持有这把锁之后，撤销不可能插进
	// 「校验 → 提交」之间：要么它先完成（本轮直接看到无效代次、不跳过），
	// 要么等本轮提交完（此时跳过基于当时仍然有效的标记）。
	resetMu sync.Mutex

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

	identities map[identityKey]identityState
	// identityGen 是每个身份的失效代次，见 InvalidateIdentity 的说明；
	// identityGenAt 记录代次最后一次推进的时刻，供 GC 判断能否清理。
	identityGen   map[identityKey]uint64
	identityGenAt map[identityKey]time.Time // 账号有效性短缓存

	// identitySeq 是代次的**全局**单调来源。
	//
	// 代次不能每身份各自从 1 开始递增：GC 会删掉长期不用的条目
	// （见 gcIdentitiesLocked），删掉之后下一次失效又从 1 开始，
	// 一个还捏着旧代次 1 的在途解析就会在回填时被判定「代次没变」
	// ——禁用前的状态被重新写回缓存，直到下一个 TTL 才纠正。
	// 全局计数器保证任何一个代次值在进程生命周期内只出现一次，
	// 回收与复用的问题一起消失。
	identitySeq uint64
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

// identityGenGrace 是失效代次在 GC 中的保留期。
//
// 代次只在「有在途解析可能还拿着它」时有意义：一次解析只是读一次库，
// 耗时远小于此，超过这个期限且没有缓存条目在用的代次就可以删掉。
//
// 这个期限**不**承担正确性：解析查询本身没有硬超时，真要有一个异常迟到的
// 解析，宽限期也保证不了它已经结束。安全性来自「代次取自全局单调计数器」
// （见 identitySeq）：条目被回收之后，任何新的失效都拿到一个从未出现过的
// 值，迟到的解析必然对不上，只会放弃回填。
const identityGenGrace = 5 * time.Minute

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
		sessions:      make(map[string]sessionInfo),
		exceeded:      make(map[uint]bool),
		blocked:       make(map[uint]bool),
		online:        make(map[uint]bool),
		lastStat:      make(map[string]trafficPair),
		touchAt:       make(map[string]time.Time),
		identities:    make(map[identityKey]identityState),
		identityGen:   make(map[identityKey]uint64),
		identityGenAt: make(map[identityKey]time.Time),
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
//
// 仅用于「不关心失效竞态」的场合（测试、显式覆盖）。业务路径应使用
// SetCachedIdentityIfGen，见下面的说明。
func (r *Runtime) SetCachedIdentity(kind uint8, id uint, active bool, version int) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[key] = identityState{active: active, version: version, at: time.Now()}
}

// IdentityGen 取某个身份的当前失效代次。
//
// 解析流程是「读库 → 算状态 → 回填缓存」，中间可能被禁用/删号/改密打断
// （InvalidateIdentity 递增代次并清缓存）。回填时只要代次变了，就说明
// 读到的是旧状态——那份结果既不能写进缓存（否则旧的有效状态会再存活
// 最多 identityTTL），也不该直接返回给这次请求。
func (r *Runtime) IdentityGen(kind uint8, id uint) uint64 {
	key := identityKey{kind: kind, id: id}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.identityGen[key]
}

// SetCachedIdentityIfGen 按代次条件回填缓存：代次一致才写入。
// 返回 false 表示期间发生了失效，调用方的读取结果已经过时。
func (r *Runtime) SetCachedIdentityIfGen(kind uint8, id uint, active bool, version int, gen uint64) bool {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.identityGen[key] != gen {
		return false
	}
	r.identities[key] = identityState{active: active, version: version, at: time.Now()}
	return true
}

// InvalidateIdentity 立即失效某个账号的缓存，并递增失效代次。
//
// 禁用 / 删除账号 / 重置密码时必须调用，否则最长会有 identityTTL 的
// 生效延迟。递增代次是为了拦住「在途的解析」：它在失效之前读的库，
// 回填时会被 SetCachedIdentityIfGen 拒绝，旧状态不会重新住进缓存。
func (r *Runtime) InvalidateIdentity(kind uint8, id uint) {
	key := identityKey{kind: kind, id: id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.identityGen == nil {
		r.identityGen = map[identityKey]uint64{}
	}
	if r.identityGenAt == nil {
		r.identityGenAt = map[identityKey]time.Time{}
	}
	// 代次取自全局单调计数器，而不是「本身份 +1」：后者在 GC 回收条目后
	// 会从 1 重新开始，与在途解析手里的旧代次撞上（见 identitySeq）。
	r.identitySeq++
	r.identityGen[key] = r.identitySeq
	r.identityGenAt[key] = time.Now()
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
	// 与采集的「校验 → 提交」互斥，见 resetMu 的说明。
	r.resetMu.Lock()
	defer r.resetMu.Unlock()
	r.unmarkTrafficResetPendingLocked(userID, gen)
}

// unmarkTrafficResetPendingLocked 与 UnmarkTrafficResetPending 语义相同，
// 但要求调用方**已持有** resetMu。
//
// 清零路径（AdminResetUserTraffic）在协调区间内写库失败后要撤销登记：
// 它已经持有 resetMu，若再走公开版本会自己把自己锁死。
func (r *Runtime) unmarkTrafficResetPendingLocked(userID uint, gen uint64) {
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

// lockTrafficReset 取得「清零协调」的互斥锁，返回释放函数。
//
// flushTraffic 用它在整轮「快照 → 事务校验 → 提交 → 摘除」期间持有，
// 撤销（UnmarkTrafficResetPending）也取同一把锁：撤销不可能插进
// 「代次校验通过」与「事务提交」之间，从而不会出现「标记已撤销、
// 这一轮却仍按它跳过了真实增量」。
func (r *Runtime) lockTrafficReset() func() {
	r.resetMu.Lock()
	return r.resetMu.Unlock
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
	now := time.Now()
	cutoff := now.Add(-maxIdle)
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

	// 身份缓存与失效代次同样要清：过期的 identities 条目以前只判未命中、
	// 不删除，identityGen 更是只增不减——长期运行、账号不断增删时，这两张
	// 表会按历史身份数一直长下去。拆出 gcIdentitiesLocked 便于测试用
	// 可控的时间点验证清理边界。
	r.gcIdentitiesLocked(now)
}

// gcIdentitiesLocked 清理过期身份缓存与失效代次（调用方须持有 r.mu）。
func (r *Runtime) gcIdentitiesLocked(now time.Time) {
	for k, st := range r.identities {
		if now.Sub(st.at) > identityTTL {
			delete(r.identities, k)
		}
	}
	for k, at := range r.identityGenAt {
		if _, cached := r.identities[k]; cached {
			continue // 还有缓存条目在用这个代次
		}
		// 留一段宽限期再清：在途解析可能已经取走了这个代次，过早删除会让
		// 它的条件写「代次对不上」而被拒绝（安全方向，只是白读一次）。
		// 宽限期远大于一次解析的耗时，实际不会误伤。
		if now.Sub(at) > identityGenGrace {
			delete(r.identityGen, k)
			delete(r.identityGenAt, k)
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
				// 到期准入刷新放在采集**之前**、且不看采集成败：
				// 它是时间驱动的，与 frps 管理接口是否可用无关。
				// 挂在采集流程里的话，frps 一挂，到期用户的标记就停在旧值
				// （清零后仍被拒 / 默认组配额调低后仍被放行）。
				s.refreshGuardDue()
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

// inQueryBatch 是 IN (?) 查询的单批参数个数。
//
// 取 500：远低于两个驱动的绑定参数上限（SQLite 32766、PostgreSQL 65535），
// 同时把一轮采集的往返次数压在个位数量级——再大只是把上限推得更近。
// 用变量而不是常量：测试里压小它才能覆盖分批逻辑。
var inQueryBatch = 500

// queryInBatches 把 ids 切成若干批逐批查询，合并结果。
//
// 一次性展开 ids 时，绑定参数个数随在线隧道数增长：撞上驱动的上限会直接
// 报错，而这条路径每 30 秒跑一次，一次失败就丢掉整轮流量采集。
//
// column 只接受内部常量（"id" / "user_id"），不来自用户输入。
// 返回顺序不保证：调用方都是建映射表，与顺序无关。
func queryInBatches[T any](db *gorm.DB, column string, ids []uint) ([]T, error) {
	var out []T
	for start := 0; start < len(ids); start += inQueryBatch {
		end := start + inQueryBatch
		if end > len(ids) {
			end = len(ids)
		}
		var batch []T
		if err := db.Where(column+" IN ?", ids[start:end]).Find(&batch).Error; err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	return out, nil
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

	// 先把代理名解析成 (用户, 隧道名)，只查这一轮真正用得到的记录。
	//
	// 以前是两张表的全量读取：每轮采集把全部用户与全部隧道读进内存建对象，
	// 而实际用到的只有 frps 当前报告的那些。默认 30 秒一轮，用户与隧道规模
	// 上来之后这些全表扫描纯属浪费——按代理集合收敛后，代价只与在线隧道数
	// 相关，与库里总共多少用户/隧道无关。
	type proxyRef struct {
		idx        int // 在 proxies 里的下标，避免重复解析代理名
		userID     uint
		tunnelName string
	}
	refs := make([]proxyRef, 0, len(proxies))
	userIDs := make([]uint, 0, len(proxies))
	seenUser := make(map[uint]bool, len(proxies))
	for i, p := range proxies {
		frpUser, tunnelName, ok := ParseProxyName(p.Name)
		if !ok {
			continue
		}
		userID, ok := UserIDFromFrpUser(frpUser)
		if !ok {
			continue
		}
		refs = append(refs, proxyRef{idx: i, userID: userID, tunnelName: tunnelName})
		if !seenUser[userID] {
			seenUser[userID] = true
			userIDs = append(userIDs, userID)
		}
	}

	// 用不可变的用户 ID 建索引：frp 的 user 字段是 lt_u<id>，与用户名无关。
	type tunnelKey struct {
		userID uint
		tunnel string
	}
	userByID := make(map[uint]*model.User, len(userIDs))
	tunnelByKey := make(map[tunnelKey]*model.Tunnel, len(refs))
	tunnelOwner := make(map[uint]uint, len(refs))
	if len(userIDs) > 0 {
		// 分批查而不是一次性展开：IN (?) 占用的绑定参数个数随在线隧道数增长，
		// SQLite 的上限是 32766（更早的编译选项下还要小），PostgreSQL 是 65535。
		// 撞上限是直接报错，而这条路径每 30 秒跑一次——一次失败就丢掉整轮采集。
		users, err := queryInBatches[model.User](s.DB, "id", userIDs)
		if err != nil {
			log.Printf("[traffic] 载入用户失败: %v", err)
			return
		}
		for i := range users {
			userByID[users[i].ID] = &users[i]
		}

		// 隧道按用户收敛，再在内存里按名字匹配：单个用户的隧道数有限，
		// 比把全表读进来便宜得多。
		tunnels, err := queryInBatches[model.Tunnel](s.DB, "user_id", userIDs)
		if err != nil {
			log.Printf("[traffic] 载入隧道失败: %v", err)
			return
		}
		for i := range tunnels {
			tunnelByKey[tunnelKey{userID: tunnels[i].UserID, tunnel: tunnels[i].Name}] = &tunnels[i]
			tunnelOwner[tunnels[i].ID] = tunnels[i].UserID
		}
	}

	tunnelDeltas := make(map[uint]*tunnelDelta, len(refs))
	userDeltas := make(map[uint]int64, len(userIDs))
	onlineNow := make(map[uint]bool, len(refs))

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
	// 先继承「今天见过的」旧基线，再覆盖本轮出现过的。
	//
	// 本轮没出现的代理**不能**直接丢掉基线：客户端重连、或 frps 分页期间
	// 发生一删一增导致漏项时，它下一轮会重新出现；那时基线若已被丢弃，
	// 就会被当成「此前从未见过」，把 frps 的**当天累计值**整个再记一遍
	// ——用户凭空多扣一大截流量，而且日志里没有任何异常。
	//
	// 只保留今天的：frps 的累计值跨零点归零，保留昨天的值反而会算错。
	// 这同时给内存规模划了界——最多是「今天出现过的代理」。
	now := time.Now()
	nextStat := make(map[string]trafficPair, len(proxies))
	for name, prev := range lastStat {
		if sameDay(prev.seenAt, now) {
			nextStat[name] = prev
		}
	}

	for _, ref := range refs {
		p := proxies[ref.idx]
		u, ok := userByID[ref.userID]
		if !ok {
			continue
		}
		t, ok := tunnelByKey[tunnelKey{userID: ref.userID, tunnel: ref.tunnelName}]
		if !ok {
			continue
		}

		cur := trafficPair{in: p.Status.TodayTrafficIn, out: p.Status.TodayTrafficOut, seenAt: now}
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
	// 未匹配到隧道的代理不进新基线（既不加进来，也不会从继承来的那份里
	// 保留——它们上轮就没被加过），等于顺手清掉了历史残留。
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
	// 这里只处理「本轮有流量」的用户；到期用户与全量校准由 refreshGuardDue
	// 在采集之外执行（frps 挂掉时也必须继续跑）。
	s.refreshGuardForTraffic(userDeltas)
}

// quotaFullRefresh 是全量准入标记校准的间隔。
//
// 常规采集轮只刷新「本轮有流量」与「计费周期到期」的用户；每 30 秒把所有
// 用户连分组一起读进内存在用户规模上来之后是纯浪费。
//
// 低频全量兜住的是那些**没有写入可挂钩**的变化，主要是分组过期：
// GroupExpireAt 到点后配额与限速回落到默认分组，数据库里没有任何一行被改。
// 代价是最多延迟这么久才纠正。
const quotaFullRefresh = 10 * time.Minute

// refreshGuardForTraffic 刷新本轮产生流量的用户的准入标记。
//
// 只刷新这些用户：超额与否只可能因用量变化，没流量的账号这一轮的输入没变。
// 「到期」用户由 refreshGuardDue 单独处理——它必须能在 frps 不可用时照常跑。
func (s *Services) refreshGuardForTraffic(userDeltas map[uint]int64) {
	if len(userDeltas) == 0 {
		return
	}
	ids := make([]uint, 0, len(userDeltas))
	for id := range userDeltas {
		ids = append(ids, id)
	}
	if err := s.refreshQuotaFlagsFor(ids); err != nil {
		log.Printf("[quota] 刷新超额标记失败: %v", err)
	}
}

// refreshGuardDue 处理「到期」用户的准入标记，并在到点时做一次全量校准。
//
// 与流量采集**解耦**执行：到期是时间驱动的，与 frps 管理接口是否可用无关。
// 挂在采集里的话（采集在 ListProxies 失败时直接返回），frps 一挂，到期用户的
// 标记就停在旧值——周期清零之后仍被拒绝，或者默认组配额调低之后仍被放行，
// 而插件的新连接准入只看这份内存标记。
func (s *Services) refreshGuardDue() {
	periodDue, groupDue, err := s.dueGuardUsers()
	if err != nil {
		log.Printf("[quota] 查询到期用户失败: %v", err)
	}

	if len(groupDue) > 0 {
		// 先落库再算标记：把到期用户迁到默认分组之后，他们不会再被每轮扫出来。
		if err := s.migrateExpiredGroups(groupDue); err != nil {
			log.Printf("[quota] 迁移到期分组用户失败（本轮仍按默认分组算标记）: %v", err)
		}
	}

	if ids := append(periodDue, groupDue...); len(ids) > 0 {
		if err := s.refreshQuotaFlagsFor(ids); err != nil {
			log.Printf("[quota] 刷新到期用户标记失败: %v", err)
		}
	}

	if s.guardFullRefreshDue() {
		// 失败时内部已记日志，这里不重复。
		_ = s.refreshQuotaFlags()
	}
}

// migrateExpiredGroups 把分组已到期的用户落到默认分组，并清掉到期时间。
//
// 只「按默认分组算配额」而不改数据是不够的：那些行会一直满足
// group_expire_at <= now，于是每一轮都被扫出来重算——历史上过期过的用户越多，
// 增量刷新的每轮开销越大，等于把「全表扫描」换成了「全历史过期扫描」。
// 落库之后条件不再命中，集合自然收敛到零；用户从此跟随默认分组，
// 管理员调整默认分组也会连带覆盖到他们（refreshQuotaForGroup 按 group_id 匹配）。
//
// 条件更新里重复了「已到期」这个前提：并发改派分组/延长有效期的操作会让它
// 落空，此时本函数什么都不做，下一次调度按新状态重新判断。
func (s *Services) migrateExpiredGroups(ids []uint) error {
	g := s.defaultGroup()
	if g == nil {
		return errors.New("没有默认分组，无法把到期用户落回默认分组")
	}
	// 分批更新：一次到期一大批用户（比如统一发过一批 30 天试用，集体到期）
	// 时，单条 IN (...) 的绑定参数会撞上驱动上限（SQLite 32766 /
	// PostgreSQL 65535），而失败后每轮调度都会原样重试一次，永远迁不完。
	now := time.Now()
	for start := 0; start < len(ids); start += inQueryBatch {
		end := start + inQueryBatch
		if end > len(ids) {
			end = len(ids)
		}
		if err := s.DB.Model(&model.User{}).
			Where("id IN ? AND group_expire_at IS NOT NULL AND group_expire_at <= ?", ids[start:end], now).
			Updates(map[string]any{"group_id": g.ID, "group_expire_at": nil}).Error; err != nil {
			return err
		}
	}
	return nil
}

// dueGuardUsers 返回本轮到期的用户 ID：计费周期结束需要清零的，
// 以及分组到期需要回落到默认分组的。
//
// 两类变化的共同点是「没有写入可挂钩」——都是时间到了才生效，任何业务路径
// 都不会主动通知。只能靠调度按「已到期」筛出来重算，所以这两列都建了索引：
// 代价与到期用户数相关，与总用户数无关。
//
// traffic_reset_at 为初始零值的用户同样会命中——那正是需要初始化周期起点的人。
//
// 两类分开返回：分组到期的那批要额外做一次「落回默认分组」的写入，
// 周期到期的只需要重算标记。合在一起会让调用方分不清该不该做迁移。
func (s *Services) dueGuardUsers() (periodDue, groupDue []uint, err error) {
	now := time.Now()

	if err := s.DB.Model(&model.User{}).
		Where("traffic_reset_at <= ?", now).
		Pluck("id", &periodDue).Error; err != nil {
		return nil, nil, err
	}

	if err := s.DB.Model(&model.User{}).
		Where("group_expire_at IS NOT NULL AND group_expire_at <= ?", now).
		Pluck("id", &groupDue).Error; err != nil {
		return periodDue, nil, err
	}
	return periodDue, groupDue, nil
}

// guardFullRefreshDue 报告是否到了全量校准的时点；到点则顺手记下本次时刻。
//
// 先记账再执行：校准失败就等下一个周期再试，而不是每轮都去撞一次可能已经
// 挂掉的数据库（「尚未就绪」由调用方单独判断，那条路径每轮重试）。
func (s *Services) guardFullRefreshDue() bool {
	now := time.Now().UnixNano()
	last := s.guardFullAt.Load()
	if last != 0 && now-last < int64(quotaFullRefresh) {
		return false
	}
	return s.guardFullAt.CompareAndSwap(last, now)
}

// refreshQuotaFlagsFor 只刷新指定用户的条件标记。
//
// 语义与全量版本一致：先取版本号、再查询、再按版本条件写；期间版本变了说明
// 有管理员动过这些账号，内存里是权威值，不能用旧快照覆盖，于是整轮重试。
//
// 与全量版本的唯一区别是**不置 guardReady**：这份快照只覆盖一部分用户，
// 不能冒充「整表已加载」——插件会据此放行没被覆盖到的账号。
func (s *Services) refreshQuotaFlagsFor(userIDs []uint) error {
	const maxPasses = 3
	for pass := 0; ; pass++ {
		ver := s.Runtime.GuardVer()

		users := make([]model.User, 0, len(userIDs))
		for start := 0; start < len(userIDs); start += inQueryBatch {
			end := start + inQueryBatch
			if end > len(userIDs) {
				end = len(userIDs)
			}
			var batch []model.User
			if err := s.DB.Preload("Group").
				Where("id IN ?", userIDs[start:end]).Find(&batch).Error; err != nil {
				return err
			}
			users = append(users, batch...)
		}

		s.applyGuardFlags(users, ver)

		if s.Runtime.GuardVer() == ver {
			return nil
		}
		if pass+1 >= maxPasses {
			log.Printf("[quota] 配额标记刷新连续 %d 轮被管理操作打断，本轮放弃（下一轮重试）", maxPasses)
			return nil
		}
	}
}

// applyGuardFlags 为一批用户重算并条件写入准入标记。
func (s *Services) applyGuardFlags(users []model.User, ver uint64) {
	for i := range users {
		s.EnsureTrafficPeriod(&users[i])
		// 快照期间该用户被管理员动过：跳过，内存里保留管理员写的权威值。
		s.Runtime.SetGuardFlagsIfVer(users[i].ID,
			s.QuotaExceeded(&users[i]),
			users[i].Status != model.UserStatusActive,
			ver)
	}
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

	// 整轮（快照 → 事务校验 → 提交 → 摘除）持清零协调锁：撤销只能发生在
	// 本轮之前或之后，不会插进「代次校验通过」与「事务提交」之间——
	// 否则清零写库失败并撤销后，这一轮仍会按已失效的标记跳过真实增量。
	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

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

	// 读回来的都是今天的行（上面的 where 已经按日期筛过），seenAt 记成此刻
	// 即可：它只用于「本轮缺席时是否保留基线」的判断，不参与增量计算。
	now := time.Now()
	m := make(map[string]trafficPair, len(rows))
	for _, r := range rows {
		m[r.ProxyName] = trafficPair{in: r.InBytes, out: r.OutBytes, seenAt: now}
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
		s.applyGuardFlags(users, ver)
		if s.Runtime.GuardVer() == ver {
			// 版本全程未变：所有条件写都生效了，整表完整，才能宣告就绪。
			s.Runtime.markAccessGuardReady()
			// 记下这次全量校准的时刻：否则启动加载完之后，紧接着的第一轮
			// 采集还会再全量扫一遍——白白多一次。
			s.guardFullAt.Store(time.Now().UnixNano())
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
