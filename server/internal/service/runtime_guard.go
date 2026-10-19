package service

import (
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

// guardRefreshInterval 是会话级准入快照的刷新间隔。
//
// 取 30 秒：最多落后一个 Ping 周期，换来的是「每次新建连接都不查库」。
// 账号禁用这类操作要求尽快生效，但不必做到实时——本地标记那条路径仍然即时，
// 这里只负责跨实例的收敛。
const guardRefreshInterval = 30 * time.Second

// guardMaxAge 是会话准入快照的最长有效期。
//
// 刷新失败（数据库不可用）时快照会停在旧值上：不设上限的话，别的实例
// 撤销会话/禁用账号之后，本实例会一直按「允许」放行——数据库故障越久，
// 这个窗口越大。5 分钟约等于 10 个刷新周期，足够熬过常见的抖动；超过
// 它就按「拒绝」处理（见 SessionGuard）。
const guardMaxAge = 5 * time.Minute

// RefreshSessionGuard 按需从库里刷新会话的准入快照。
//
// 只在 Ping 路径调用：那是周期性事件，不是每次新建连接。
// 读库失败时保持原判（不清标记）——「已知但略旧」比「未知」安全。
func (s *Services) RefreshSessionGuard(runID string) {
	if runID == "" {
		return
	}
	sess, ok := s.Runtime.LookupSession(runID)
	if !ok {
		return
	}
	if !sess.GuardAt.IsZero() && time.Since(sess.GuardAt) < guardRefreshInterval {
		return
	}
	var u model.User
	err := s.DB.Preload("Group").First(&u, sess.UserID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 账号在别的实例被删掉了：数据库会话与用户记录一起没了，而本机内存
		// 会话还在。这时不能「保持原判」——旧客户端会一直 Ping，本机就一直
		// 留着这个会话，已有隧道继续接受新连接。
		s.Runtime.SetSessionGuard(runID, true, true)
		return
	}
	if err != nil {
		// 数据库暂时不可用：保持原判。此时「已知但略旧」比「未知」安全。
		return
	}
	// 数据库里的会话状态也要复核：别的实例重置密码/注销会话后会把这里标成
	// 离线，而本机内存会话还在——不查的话旧 frpc 会一直能建新连接。
	// 查不到（或已过期）按「已禁用」处理，让下一次建连被拒。
	if _, err := s.FindTrustedClientSession(runID); err != nil {
		s.Runtime.SetSessionGuard(runID, true, s.QuotaExceeded(&u))
		return
	}
	s.Runtime.SetSessionGuard(runID,
		u.Status != model.UserStatusActive,
		s.QuotaExceeded(&u))
}

// sessionAliveTTL 是「会话仍在线」的核验间隔。
//
// 撤销（改密/重置/轮换 secret）之后旧客户端不该再建连接。单实例下本地
// 清会话就是即时的；多实例下必须回查数据库，而每次新建连接都查会把这
// 条热路径压到数据库上。
//
// 1 秒是本实现能给出的上界，不是理想值。要做到严格立即失效只有两条路：
//   - 每次新建连接都查库：SQLite 单写者模型下，一个刷连接的脚本就能把
//     登录与插件回调一起拖慢，等于用可用性换一致性；
//   - 撤销方广播失效事件：项目没有事件总线，多实例之间没有通道。
//
// 因此这里如实标注：撤销最坏延迟 1 秒。真要做到即时，需要引入共享存储
// 或消息通道，那是部署层的决定，不该由这个常量假装解决。
const sessionAliveTTL = time.Second

// EnsureSessionOnline 复核会话在数据库里是否仍然有效。
//
// 返回 false 表示已被撤销（或账号已删），调用方应当拒绝本次请求。
// 内存会话不存在时也返回 false：那种情况下调用方本来就会回落数据库。
func (s *Services) EnsureSessionOnline(runID string) bool {
	if runID == "" {
		return false
	}
	sess, ok := s.Runtime.LookupSession(runID)
	if !ok {
		return false
	}
	if !sess.AliveCheckedAt.IsZero() && time.Since(sess.AliveCheckedAt) < sessionAliveTTL {
		return !sess.Revoked
	}
	alive := true
	if _, err := s.FindTrustedClientSession(runID); err != nil {
		alive = false
	}
	s.Runtime.SetSessionAlive(runID, alive)
	return alive
}

// SessionGuard 返回会话级准入快照，ok=false 表示快照尚未建立。
//
// 代理注册与新连接两条路径共用它：两边各查各的（一个看全局缓存、一个看快照）
// 会让多副本下的决策互相矛盾——配额刚放宽时代理注册仍被拒，或会话已撤销却
// 注册成功、后续连接全被拒。
func (s *Services) SessionGuard(runID string) (blocked, exceeded, ok bool) {
	if runID == "" {
		return false, false, false
	}
	sess, found := s.Runtime.LookupSession(runID)
	if !found || sess.GuardAt.IsZero() {
		return false, false, false
	}
	// 快照超过最长有效期，说明这些轮刷新一直没成功（数据库不可用）。
	// 此时旧的「允许」不能继续生效：别的实例可能已经撤销了会话或禁用了
	// 账号，而本实例拿着一个再也刷不新的快照在放行新连接。
	// 方向取拒绝——数据库故障期间牺牲一点可用性，好过让已撤销的会话
	// 无限期有效。
	if time.Since(sess.GuardAt) > guardMaxAge {
		return true, sess.Exceeded, true
	}
	return sess.Blocked, sess.Exceeded, true
}

// PrimeSessionGuard 用刚读到的用户数据初始化会话的准入快照。
//
// 用于「从数据库回填会话」的路径：新会话的 GuardAt 是零值，若不立刻初始化，
// 在这台实例收到下一次 Ping 之前，新建连接只能依赖本机的配额缓存——
// 多副本时那份缓存可能已经落后于别的实例上的配额/禁用变更。
func (s *Services) PrimeSessionGuard(runID string, u *model.User) {
	if runID == "" || u == nil {
		return
	}
	// QuotaExceeded 需要分组信息；调用方给的 user 不一定预加载了关联。
	if u.Group == nil && u.GroupID != 0 {
		var g model.Group
		if err := s.DB.First(&g, u.GroupID).Error; err == nil {
			u.Group = &g
		}
	}
	s.Runtime.SetSessionGuard(runID,
		u.Status != model.UserStatusActive,
		s.QuotaExceeded(u))
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
		} else {
			// 分组已变化：推进准入版本，让在途的旧分组快照写不进内存标记，
			// 否则用户在下一轮校准前仍沿用旧分组配额。
			s.Runtime.BumpGuardVer()
		}
	}

	if ids := append(periodDue, groupDue...); len(ids) > 0 {
		if err := s.refreshQuotaFlagsFor(ids); err != nil {
			log.Printf("[quota] 刷新到期用户标记失败: %v", err)
			// 这批用户刚刚被迁回默认分组，下一轮不会再出现在「已到期」集合里。
			// 本轮刷新失败若不补偿，旧的内存准入标记会一直留在原处——插件
			// 热路径只看内存，用户按旧分组配额被拒绝或放行，而数据库里
			// 一切正常，没有任何地方会再纠正它。
			//
			// 把全量校准的时点清零：下一轮用一次全量扫描把这些人收回来。
			// 代价是一次额外的全表读，且只在真实失败时发生。
			s.guardFullAt.Store(0)
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
	// 分批更新：一次到期一大批用户（比如统一发过一批 30 天试用，集体到期）
	// 时，单条 IN (...) 的绑定参数会撞上驱动上限（SQLite 32766 /
	// PostgreSQL 65535），而失败后每轮调度都会原样重试一次，永远迁不完。
	now := time.Now()
	for start := 0; start < len(ids); start += inQueryBatch {
		end := start + inQueryBatch
		if end > len(ids) {
			end = len(ids)
		}
		// 用户回落与隧道限速快照必须在同一个事务里改完：先迁用户再单独
		// 刷新隧道，中间的崩溃会留下「用户已按默认分组计费、隧道仍写着旧
		// 分组的限速」这种没有任何调度会纠正的状态（这批用户已经不满足
		// 「已到期」条件，不会再被扫出来）。
		if err := s.DB.Transaction(func(tx *gorm.DB) error {
			batch := ids[start:end]
			// 在事务内、按行锁重新确认「确实还是过期的」。
			//
			// 到期名单来自调度开始时的查询：这期间管理员可能延长了某人的
			// 有效期。无条件按 batch 刷新隧道的话，那些人的隧道会被写成
			// 默认分组限速，而他们的用户行仍留在原分组——两处长期不一致，
			// 且不会再有调度来纠正（他们已经不满足「已到期」条件）。
			var still []uint
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Model(&model.User{}).
				Where("id IN ? AND group_expire_at IS NOT NULL AND group_expire_at <= ?", batch, now).
				Pluck("id", &still).Error; err != nil {
				return err
			}
			if len(still) == 0 {
				return nil
			}
			// 默认分组同样在事务内、加锁读取：与管理员并发改默认组时，
			// 读到的必须是这次写入生效的那个分组，否则快照会写成上一个
			// 默认组的限速。
			g := s.defaultGroupTx(tx)
			if g == nil {
				return errors.New("没有默认分组，无法把到期用户落回默认分组")
			}
			if err := tx.Model(&model.User{}).
				Where("id IN ?", still).
				Updates(map[string]any{"group_id": g.ID, "group_expire_at": nil}).Error; err != nil {
				return err
			}
			// 快照同步到生效分组；trigger 会同时推进隧道清单版本，客户端
			// 下一次同步就能看到新的限速。
			return tx.Model(&model.Tunnel{}).Where("user_id IN ?", still).
				Update("bandwidth_limit", g.BandwidthLimit).Error
		}); err != nil {
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
