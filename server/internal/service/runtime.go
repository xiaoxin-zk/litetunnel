package service

import (
	"errors"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// sessionInfo 一次 frpc 登录会话的缓存，避免插件回调频繁打库。
type sessionInfo struct {
	UserID   uint
	Username string
	LastSeen time.Time

	// GuardAt / Blocked / Exceeded 是**会话级**的准入快照，随 Ping 定期从库里刷新。
	//
	// 多副本下每个实例都有独立的内存标记：账号在别的实例被禁用后，本实例的
	// 标记要等重启或全量刷新才会变，这段时间里插件会继续放行。改成按会话刷新
	// 之后，最多一个 Ping 周期就能拦住，而且不需要在每次新建连接时查库。
	GuardAt  time.Time
	Blocked  bool
	Exceeded bool

	// AliveCheckedAt / Revoked 是「这个会话在数据库里是否还有效」的短周期核验。
	//
	// 会话撤销（改密、重置密码、轮换 client secret）只发生在某一台实例上：
	// 它清掉自己的内存会话并把数据库里的会话置为离线，其它实例的内存会话
	// 不会跟着消失。准入快照要等一个 Ping 周期（30 秒）才刷新，而旧 frpc
	// 在这段时间里可以继续建新代理——改密的语义是「立刻把旧客户端踢掉」，
	// 不该留这么久。
	AliveCheckedAt time.Time
	Revoked        bool
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

	// resetMarkSeedPending 表示「清零代次标记表首次启用后的第一轮」尚未完成。
	//
	// 与 baselineSeedPending 分开记：基线就绪不代表标记就绪。旧库升级上来时
	// 有基线、没有标记，若停机期间清零过，首轮会把「没有记录」当成「没变」，
	// 把清零前的流量加回来。首轮按保守策略跳过增量、顺带写入标记即可。
	resetMarkSeedPending bool

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

	// lastResetGen 记录「上次成功提交时」各用户的清零代次（users.traffic_reset_gen）。
	//
	// 进程内的 pendingTrafficReset 只对当前实例可见；清零请求落在别的实例时，
	// 采集侧只能靠库里的代次发现「这中间被清零过」。没有上次记录的用户
	// （刚启动/刚接管）按「没变」处理——宁可少丢一轮，也不要一次重启吞掉
	// 所有人的一轮用量。唯一的例外是标记表首次启用时写下的哨兵值
	// （见 resetGenUnknown）：那表示「这份基线对应的代次无从判断」，
	// 必须按变过处理。
	lastResetGen map[uint]int64

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
	// 写失败会让陈旧会话一直挂在「在线」列表里，虽然信任校验还有 last_seen_at
	// 窗口兜底（不影响准入），但后台在线数会失真，因此要留下线索。
	if err := s.DB.Model(&model.ClientSession{}).
		Where("online = ? AND last_seen_at < ?", true, cutoff).
		Update("online", false).Error; err != nil {
		log.Printf("[session] 标记陈旧会话离线失败（在线列表可能残留幽灵会话）: %v", err)
		s.recordAuditFailure(auditScopeSessionSweep, err)
	}
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

// SetSessionGuard 写入会话级的准入快照（见 sessionInfo.GuardAt）。
func (r *Runtime) SetSessionGuard(runID string, blocked, exceeded bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.Blocked = blocked
		s.Exceeded = exceeded
		s.GuardAt = time.Now()
		r.sessions[runID] = s
	}
}

// SetSessionAlive 记录一次会话有效性核验的结果。
func (r *Runtime) SetSessionAlive(runID string, alive bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.AliveCheckedAt = time.Now()
		s.Revoked = !alive
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

// tunnelOnlineGrace 是「在线」的判定窗口。
//
// 采集器每轮把在线隧道的 last_online_at 写成当前时间，接口按它判断在线。
// 窗口取两个采集周期（下限 60 秒），留出抖动余量：窗口太小会让一轮延迟
// 就闪成离线，太大则断线后迟迟不显示离线。
func (s *Services) tunnelOnlineGrace() time.Duration {
	grace := 2 * s.Cfg.TrafficPollInterval
	if grace < time.Minute {
		grace = time.Minute
	}
	return grace
}

// IsTunnelOnline 判断隧道是否在线（以数据库里的最后在线时间为准）。
//
// 不用进程内的在线集合：多副本时只有持有采集租约的实例会更新它，
// 其他实例的用户接口会一直显示离线。last_online_at 由采集器写库，谁读都对。
func (s *Services) IsTunnelOnline(t *model.Tunnel) bool {
	if t == nil || t.LastOnlineAt == nil {
		return false
	}
	return time.Since(*t.LastOnlineAt) <= s.tunnelOnlineGrace()
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
