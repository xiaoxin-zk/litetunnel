package service

// 本文件是代理断流的「持久化残留」阶段：待办落库与后台重试器。
//
// # 为什么必须落库
//
// 断流要访问 frps 管理接口，而它是外部依赖：重启、升级、网络抖动都会让它
// 短暂不可用。原先的实现在 ListProxies 失败时直接 return 0——那次断流就
// 永久消失了。已建立的代理流不经过任何准入判断，会一直转发到客户端自己
// 退出，于是出现最不该有的状态：账号在面板上已经禁用/删除了，流量还在跑，
// 从任何界面上都看不出来。
//
// 落库之后，重启只是「换个人继续关」：后台重试器按 NextAt 到期再试，直到
// 关干净才删掉这一行。这与 firewall_pending.go 的取舍完全一致——那边的
// 「本该收回的端口一直开着」和这边的「本该断掉的流量一直跑着」是同一类
// 故障：数据库状态已经改了，外部动作没做成，而没有任何地方会再试一次。
//
// # 退避
//
// 基础 30 秒、每次翻倍、上限 30 分钟、最多 10 次（约两小时）。理由：
//
//   - 下限 30 秒：frps 重启通常几秒到几十秒，比这更密的重试只是刷日志；
//   - 上限 30 分钟：frps 长时间不可用时也不该无限期地每秒试一次，但也不能
//     放弃得太早——禁用/删除是安全动作，代理一直开着就是持续泄漏；
//   - 到上限后**保留记录**（exhausted），而不是删掉：删了之后「这个已删除
//     账号的代理可能还在跑」就再没有任何线索，只剩一行迟早被滚动掉的日志。
//
// # 跨实例
//
// 多实例共用一个库时，每个进程都会跑重试器。领取用条件更新（把 next_at
// 推到租约到期时间）实现，只有成功的那一个实例动手，实例崩溃后租约自然
// 过期、别的实例接手。Fence 围栏令牌保证「被别的实例接手之后，旧持有者的
// 回写不会覆盖新状态」。

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	// proxyDrainRetryInterval 是重试器的轮询间隔。
	//
	// 30 秒与发件箱一致：待办本来就少，轮询只查一条带索引的 next_at 条件，
	// 开销可以忽略；比这更密没有意义，更疏则会拖慢 frps 恢复后的补偿。
	proxyDrainRetryInterval = 30 * time.Second
	// proxyDrainBaseDelay 是首次失败后的重试间隔。
	proxyDrainBaseDelay = 30 * time.Second
	// proxyDrainMaxDelay 是退避上限。
	proxyDrainMaxDelay = 30 * time.Minute
	// proxyDrainMaxAttempts 是同一份待办的最大重试次数。
	//
	// 到上限后进入终态（Exhausted），记录保留待人工排查。
	proxyDrainMaxAttempts = 10
	// proxyDrainLease 是单份待办的领取租期。
	//
	// 必须长于一轮断流的最坏耗时（closeProxiesTimeout = 15 秒）：短于它的话，
	// 正常处理中的待办会被另一个实例抢走，两边同时关闭代理——虽然关闭是
	// 幂等的，但重复的日志会让「到底谁关的」无从追溯。
	proxyDrainLease = closeProxiesTimeout + 30*time.Second
	// proxyDrainBatchSize 是单轮最多处理的待办数。
	//
	// 限批而不是一次全取：单份待办最坏耗时 15 秒，一次取几十份会把这一轮
	// 拖到十几分钟，期间新产生的待办只能在后面排着。
	proxyDrainBatchSize = 8
)

// proxyDrainRetryDelay 计算第 n 次失败后的重试间隔（指数退避，带上限）。
//
// 与 mailRetryDelay 同一个形状：起步 30 秒、每次翻倍、到 30 分钟封顶。
// 单独一个函数而不是内联，是为了让「退避递增且有上限」这件事可以被单元
// 测试直接断言——靠集成测试观察时间间隔既慢又不稳定。
func proxyDrainRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := proxyDrainBaseDelay
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= proxyDrainMaxDelay {
			return proxyDrainMaxDelay
		}
	}
	return d
}

// proxyDrainTargetsJSON 把发现的实例身份快照序列化进待办。
//
// 序列化失败只记日志并落空串：快照是**加密级判据**，不是流程必需物——没有
// 它只是退化成按时间水位判断（见 retryPendingProxyDrains 的说明），而因为
// 一次编码失败让整条待办落不了库，就等于放弃了唯一的补偿机会。
func proxyDrainTargetsJSON(targets []proxyDrainTarget) string {
	if len(targets) == 0 {
		return ""
	}
	raw, err := json.Marshal(targets)
	if err != nil {
		log.Printf("[proxy-drain] 实例身份快照序列化失败（退化为按时间水位判断）: %v", err)
		return ""
	}
	return string(raw)
}

// decodeProxyDrainTargets 还原待办里的实例身份快照。
//
// 解不出来时返回空切片并记日志：与上面同一个取舍——宁可退化成保守判断，
// 也不要因为一条脏数据让整个重试循环报错停摆。
func decodeProxyDrainTargets(raw string) []proxyDrainTarget {
	if raw == "" {
		return nil
	}
	var out []proxyDrainTarget
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Printf("[proxy-drain] 待办里的实例身份快照无法解析，按空快照处理: %v", err)
		return nil
	}
	return out
}

// recordProxyDrainPending 在动手之前把这次断流意图落库，返回本次意图的围栏令牌。
//
// 返回空串表示**没有**写进去（数据库故障，或已有更强的意图在等重试）。
// 调用方据此仍然继续断流（能关一个是一个），只是这次失败将没有补偿机会。
//
// # 为什么先落库再断流
//
// 反过来的顺序有一个无法消除的窗口：断流失败（或进程恰好在这两步之间退出）
// 时待办根本不存在，补偿机会彻底丢失——这正是缺陷 1 的形态。先落库最坏只是
// 留下一条「其实已经关干净了」的待办，下一轮发现没有残留就删掉，代价是一次空转。
//
// # 覆盖规则
//
// 一个用户一条待办，后来的意图覆盖先前的（与 FirewallPending 按端口收敛同理）：
//   - 删号意图**优先**于禁用意图：账号都没了，「断开禁用前的流量」这件事
//     已经不需要区分，关干净就对了；反过来让禁用意图覆盖删号意图，会让
//     已删除账号的残留代理失去补偿。
//   - 同为禁用意图时按 StatusGen 取大：状态版本单调，代次更大的意图更新。
//
// 条件写放在数据库里（ON CONFLICT ... WHERE），而不是「先读后写」：多实例
// 并发登记时，读到的可能都不是最新值，条件写才是原子的。表达式刻意不用
// 数字字面量比较布尔列——SQLite 存 0/1、Postgres 是真 boolean，
// `deleted = 1` 在 Postgres 上会直接类型错误。
func (s *Services) recordProxyDrainPending(req proxyDrainRequest) string {
	return s.recordProxyDrainPendingDB(s.DB, req)
}

// recordProxyDrainPendingDB 在给定数据库句柄上登记断流意图。
// 事务内调用时传入事务句柄，使「账号禁用」与「断流意图」在同一个提交点落地。
func (s *Services) recordProxyDrainPendingDB(db *gorm.DB, req proxyDrainRequest) string {
	if db == nil {
		return ""
	}
	fence, err := randomHex(16)
	if err != nil {
		log.Printf("[proxy-drain] 生成待办围栏令牌失败（用户 %d）: %v", req.userID, err)
		return ""
	}
	// 记录登记那一刻的账号标识：账号被删除后 ID 若被导入/恢复流程复用，
	// 新账号会拿到不同标识，这条旧待办据此作废，而不是按相同前缀关掉
	// 新账号刚建立的代理。读不到账号时留空，空的待办在重试时按「不可核验」
	// 处理，不会退化成不校验。
	var incarnation string
	{
		var u model.User
		if err := db.Select("id", "incarnation").First(&u, req.userID).Error; err != nil {
			log.Printf("[proxy-drain] 读取用户 %d 的账号标识失败（待办仍会登记，重试时按不可核验处理）: %v",
				req.userID, err)
		} else {
			incarnation = u.Incarnation
		}
	}
	rec := model.ProxyDrainPending{
		UserID:      req.userID,
		Incarnation: incarnation,
		Prefix:      req.prefix,
		StatusGen:   req.gen,
		NotAfter:  unixOrZero(req.notAfter),
		Deleted:   req.deleted,
		IntentAt:  time.Now().Unix(),
		Targets:   proxyDrainTargetsJSON(req.known),
		Attempts:  0,
		NextAt:    time.Now().Add(proxyDrainBaseDelay),
		Fence:     fence,
	}
	res := db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			// incarnation 只在新值非空时覆盖。
			//
			// 删号路径的即时断流与后台重试都发生在 users 行删除**之后**，
			// 此刻读不到账号标识。若无条件写回，事务内记下的那个标识会被
			// 空值抹掉，ID 被复用时这条旧待办就失去了唯一可核验的依据。
			"incarnation": gorm.Expr(`CASE WHEN excluded.incarnation <> ''
				THEN excluded.incarnation ELSE lt_proxy_drain_pending.incarnation END`),
			"prefix":     gorm.Expr("excluded.prefix"),
			"status_gen": gorm.Expr("excluded.status_gen"),
			"not_after":  gorm.Expr("excluded.not_after"),
			"deleted":    gorm.Expr("excluded.deleted"),
			"intent_at":  gorm.Expr("excluded.intent_at"),
			"targets":    gorm.Expr("excluded.targets"),
			// exhausted 与 attempts 一起重置：新的意图该有自己完整的一轮预算。
			// 沿用旧的「已耗尽」会让这次断流第一次失败就再被判为终态，等于
			// 永久拒绝为这个账号做补偿。
			"attempts":   gorm.Expr("excluded.attempts"),
			"exhausted":  gorm.Expr("excluded.exhausted"),
			"next_at":    gorm.Expr("excluded.next_at"),
			"fence":      gorm.Expr("excluded.fence"),
			"last_err":   gorm.Expr("excluded.last_err"),
			"updated_at": time.Now(),
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			// 条件写分两层，理由见函数注释。刻意用布尔列本身做判断而不写
			// `deleted = 1`：SQLite 存 0/1，PostgreSQL 是真 boolean，
			// 拿数字字面量去比在 Postgres 上会直接类型错误。
			gorm.Expr(`(excluded.deleted AND NOT lt_proxy_drain_pending.deleted)
				OR (excluded.deleted = lt_proxy_drain_pending.deleted
				    AND excluded.status_gen >= lt_proxy_drain_pending.status_gen)`),
		}},
	}).Create(&rec)
	if res.Error != nil {
		log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败（本次若也没关干净，重启后将没有补偿机会）: %v",
			req.userID, res.Error)
		return ""
	}
	// 是否由本次意图占住了这一行，用**读回**判断而不是 RowsAffected：
	// 「ON CONFLICT DO UPDATE ... WHERE 不成立」时不同驱动给出的受影响行数
	// 并不一致，据此认领会把「被更强意图拒绝」误判成「我登记成功」，随后
	// 拿错误的围栏令牌去收尾别人的待办（把那条真正该执行的断流删掉）。
	var mine int64
	if err := db.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ?", req.userID, fence).Count(&mine).Error; err != nil {
		log.Printf("[proxy-drain] 读回用户 %d 的断流待办失败: %v", req.userID, err)
		return ""
	}
	if mine == 0 {
		// 已被更强的意图占着（删号意图 / 更新的状态代次）：本次不覆盖，也不认领。
		// 那条更强的意图本来就会被后台重试，本次的残留由它兜住。
		return ""
	}
	return fence
}

// clearProxyDrainPending 删除本次意图的待办，但只删围栏令牌仍是自己的那一行。
//
// 无条件按 UserID 删会把期间登记的新意图一起删掉：那条真正需要执行的断流
// 就再也不会被重试，而它的失败**不会报错**——只是账号的代理一直跑着。
func (s *Services) clearProxyDrainPending(userID uint, fence string) {
	if fence == "" || s.DB == nil {
		return
	}
	if err := s.DB.Where("user_id = ? AND fence = ?", userID, fence).
		Delete(&model.ProxyDrainPending{}).Error; err != nil {
		log.Printf("[proxy-drain] 清除用户 %d 的断流待办失败（下轮会把空转再跑一遍，不影响正确性）: %v",
			userID, err)
	}
}

// rescheduleProxyDrain 把未关干净的残留重新登记：累计次数、退避下一次时间、
// 更新实例身份快照；到上限则转终态并保留记录。
func (s *Services) rescheduleProxyDrain(req proxyDrainRequest, out proxyDrainOutcome) {
	if s.DB == nil {
		return
	}
	if req.intent == "" {
		// 意图没落库：两种情况——数据库故障，或已有更强的待办覆盖了本次。
		//
		// 两种情况都**不能只记日志**（缺陷 4）：前者说明这次残留没有任何
		// 持久化补偿，必须进进程内队列等数据库恢复；后者虽然已有待办兜底，
		// 但那条待办可能是「禁用」而本次是「删号」（更强的语义），补写一次
		// 无害且更准确——recordProxyDrainPending 的覆盖规则会自己判断。
		if s.drainFallback != nil {
			s.drainFallback.enqueue(req)
			log.Printf("[proxy-drain] 用户 %d 仍有 %d 个代理未能关闭，本次意图未落库，已放入进程内补偿队列",
				req.userID, len(out.residual))
		} else {
			log.Printf("[proxy-drain] 用户 %d 仍有 %d 个代理未能关闭，但本次意图没有落库且无补偿队列（数据库故障），由现有待办的后台重试兜底",
				req.userID, len(out.residual))
		}
		return
	}

	attempts := req.attempts + 1
	delay := proxyDrainRetryDelay(attempts)
	exhausted := attempts >= proxyDrainMaxAttempts

	updates := map[string]any{
		"attempts": attempts,
		"next_at":  time.Now().Add(delay),
		"last_err": truncate(out.lastErr, 255),
	}
	// 快照只在真的发现了残留时替换：列表拉取失败（unknown）时保留上一次的
	// 快照，说明白点就是「上次打算关这些，这次连世界长什么样都没看见」。
	if len(out.residual) > 0 {
		updates["targets"] = proxyDrainTargetsJSON(out.residual)
	}
	if exhausted {
		// 终态：不再重试，记录保留。时间仍往后推，避免每轮都被扫出来。
		updates["exhausted"] = true
		updates["next_at"] = time.Now().Add(proxyDrainMaxDelay)
	}

	res := s.DB.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ?", req.userID, req.intent).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[proxy-drain] 更新用户 %d 的断流待办失败（下一轮仍会按旧时间重试）: %v",
			req.userID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		// 期间被更强的意图覆盖了：本次的残留自然由那条意图负责，不能再去动它。
		return
	}
	if exhausted {
		log.Printf("[proxy-drain] 用户 %d 的断流连续 %d 次未能完成，已停止自动重试（待办保留：user_id=%d prefix=%s last_err=%s），"+
			"已建立的代理可能仍在转发流量，请人工排查 frps 管理接口或该前缀下的代理",
			req.userID, attempts, req.userID, req.prefix, truncate(out.lastErr, 200))
	}
}

// unixOrZero 把时刻转成 Unix 秒；零值（禁用路径之外的删除路径）保持 0。
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeFromUnix 还原时刻；0 表示「没有水位」，返回零值。
func timeFromUnix(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// requestFromPending 按落库待办重建一次断流请求。
//
// 重建出来的判据必须与原意图完全一致（deleted / gen / notAfter / 前缀 / 快照），
// 否则「重试」就变成了另一种更宽松的关闭逻辑——那正是「按名字盲关」的来源。
func requestFromPending(row model.ProxyDrainPending) proxyDrainRequest {
	req := proxyDrainRequest{
		userID:   row.UserID,
		prefix:   row.Prefix,
		gen:      row.StatusGen,
		notAfter: timeFromUnix(row.NotAfter),
		deleted:  row.Deleted,
		attempts: row.Attempts,
		intent:   row.Fence,
		known:    decodeProxyDrainTargets(row.Targets),
	}
	if req.prefix == "" {
		req.prefix = FrpUserOf(req.userID) + "."
	}
	// 删除路径没有禁用时刻可用。补一个时间水位：待办登记**之后**才启动的代理
	// 说明是客户端重连重新注册的新实例（账号都删了，不可能再有合法的重新
	// 注册），关它就是误杀。用登记时刻而不是「现在」，才能保证多轮重试之间
	// 水位不漂移——否则每轮重试都会把上一轮之后新出现的代理当成合法目标。
	//
	// 优先用 IntentAt（随每次意图覆盖刷新）；只有老记录（该列还是 0）才退回
	// CreatedAt。不用 CreatedAt 作主判据的原因见模型注释：意图被覆盖时它不变，
	// 水位会往前漂，漂得越早越是偏向误杀。
	if req.deleted && req.notAfter.IsZero() {
		switch {
		case row.IntentAt > 0:
			req.notAfter = timeFromUnix(row.IntentAt)
		case !row.CreatedAt.IsZero():
			req.notAfter = row.CreatedAt
		}
	}
	return req
}

// claimProxyDrain 领取一份到期待办，成功时把新的围栏令牌写回 row。
//
// 领取是条件更新：只有把 next_at 推进成功的那一个实例在租期内独占。同时
// **轮换围栏令牌**——实例 A 领取后卡死、租约过期被 B 接手，A 醒来时的回写
// 必须被拒，不能覆盖 B 的状态（与 MailOutbox.ClaimToken 同一个理由）。
func (s *Services) claimProxyDrain(row *model.ProxyDrainPending, now time.Time) bool {
	fence, err := randomHex(16)
	if err != nil {
		log.Printf("[proxy-drain] 生成领取令牌失败（用户 %d）: %v", row.UserID, err)
		return false
	}
	res := s.DB.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ? AND next_at <= ? AND exhausted = ?",
			row.UserID, row.Fence, now, false).
		Updates(map[string]any{
			"fence":   fence,
			"next_at": now.Add(proxyDrainLease),
		})
	if res.Error != nil {
		log.Printf("[proxy-drain] 领取待办失败（用户 %d）: %v", row.UserID, res.Error)
		return false
	}
	if res.RowsAffected != 1 {
		// 被别的实例抢先领走了。多实例共用一个库时这是常态，不是异常。
		return false
	}
	row.Fence = fence
	return true
}

// proxyDrainIntent 是重试前对「这条待办还算不算数」的判定。
//
// 三种结果必须分开，因为收尾动作完全不同：作废要删待办且一条代理都不许关；
// 不可核验要保留待办、这轮什么都不做（数据库抖动而已）；有效才继续断流。
type proxyDrainIntent int

const (
	// proxyDrainIntentActive 意图仍然成立，可以继续关。
	proxyDrainIntentActive proxyDrainIntent = iota
	// proxyDrainIntentAbandoned 账号在待办登记之后被重新启用（状态版本已变），
	// 这条意图作废：继续关就是把刚放行的人踢下线。
	proxyDrainIntentAbandoned
	// proxyDrainIntentUnverifiable 查不到状态版本（数据库暂时不可用）。
	//
	// 与作废必须分开：读不出来不是「已经变了」，据此删待办等于在数据库抖动时
	// 悄悄放弃一次安全动作。
	proxyDrainIntentUnverifiable
)

// proxyDrainIntentState 在动手之前复核这条待办是否仍然成立，返回判定与
// 「重试时该按删号语义处理吗」。
//
// 第二个返回值为 true 的两种情形：
//   - 待办本来就登记为删号（row.Deleted）；
//   - 禁用之后账号又被删掉了：此时不存在「重新启用」的可能，也没有
//     users.state_version 可读，继续按删号语义（前缀 + 实例身份）关干净。
//
// 这正是任务要求的「复用 gen / notAfter / deleted 三条判据」，而不是退化成
// 「按名字盲关」：状态版本决定要不要动手，notAfter 决定关哪些名字。
func (s *Services) proxyDrainIntentState(row model.ProxyDrainPending) (proxyDrainIntent, bool) {
	if row.Deleted {
		// 账号已删：没有「重新启用」这回事，按删号语义继续——
		// 但必须先排除「这个 ID 已经被另一个账号占用」。导入/恢复流程复用
		// 自增 ID 时，旧删号待办的前缀与新账号完全相同，照着关就会打掉
		// 新账号刚建立的代理。此刻用户行存在即说明 ID 已被复用，旧意图作废。
		if row.Incarnation != "" {
			if _, inc, err := s.userStateVersionAndIncarnation(row.UserID); err == nil && inc != row.Incarnation {
				log.Printf("[proxy-drain] 已删账号 %d 的 ID 已被新账号占用（%s ≠ %s），旧删号意图作废",
					row.UserID, row.Incarnation, inc)
				return proxyDrainIntentAbandoned, false
			}
		}
		return proxyDrainIntentActive, true
	}
	gen, incarnation, err := s.userStateVersionAndIncarnation(row.UserID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 禁用之后账号被删了：断流目标没变（还是那批代理），语义换成删号。
		return proxyDrainIntentActive, true
	}
	if err != nil {
		log.Printf("[proxy-drain] 用户 %d 的状态版本读取失败，本轮不动手（保留待办继续重试）: %v",
			row.UserID, err)
		return proxyDrainIntentUnverifiable, false
	}
	if row.Incarnation != "" && incarnation != row.Incarnation {
		// 同一个自增 ID 已经是另一个账号（导入/恢复/手工重建）。旧待办描述的
		// 是上一个生命周期，按相同前缀去关只会打掉新账号的代理。
		log.Printf("[proxy-drain] 用户 %d 的账号标识已变化（%s ≠ %s），旧断流意图作废",
			row.UserID, row.Incarnation, incarnation)
		return proxyDrainIntentAbandoned, false
	}
	if gen != row.StatusGen {
		// 账号已被重新启用（也可能是又禁用了一次）：这条意图对应的那次禁用
		// 已经不是当前状态，手里的代理清单描述的世界已经过去了。
		return proxyDrainIntentAbandoned, false
	}
	return proxyDrainIntentActive, false
}

// ProxyDrainQueueHealth 是断流待办队列的可观测快照。
//
// 为什么单独暴露：frps 管理接口不可用时，重试循环刻意「保留待办但不推进」
// （见 retryPendingProxyDrains 的 Frps == nil 分支）。这条路径不报错、也不
// 改 next_at，从日志里只能看到一次启动日志，管理员无从知道「有 N 个账号的
// 代理其实一直没被关掉」。把队列深度与依赖可用性放到系统指标里，才能让
// 这种「静默但不危险」的状态被发现。
type ProxyDrainQueueHealth struct {
	// Pending 是仍在等待重试的待办数（不含已停止自动重试的终态）。
	Pending int64 `json:"pending"`
	// Exhausted 是已停止自动重试、等待人工处理的待办数。
	Exhausted int64 `json:"exhausted"`
	// NextAttemptAt 是最早的一条待办的预定重试时刻（nil 表示没有待办）。
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	// FrpsAvailable 表示当前进程有没有可用的 frps 管理客户端。
	// false 且 Pending > 0 就是「待办永远不会推进」的明确信号。
	FrpsAvailable bool `json:"frps_available"`
	// LastErr 是最近一条待办登记的错误摘要，便于判断是网络还是权限问题。
	LastErr string `json:"last_err,omitempty"`
}

// ProxyDrainQueueHealth 读取待办队列状态。查询失败时返回零值并记录日志：
// 这是只读观测接口，不能因为数据库抖动把系统指标整体打挂。
func (s *Services) ProxyDrainQueueHealth() ProxyDrainQueueHealth {
	h := ProxyDrainQueueHealth{FrpsAvailable: s != nil && s.Frps != nil}
	if s == nil || s.DB == nil {
		return h
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", false).Count(&h.Pending).Error; err != nil {
		log.Printf("[proxy-drain] 统计待办数量失败: %v", err)
		return h
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", true).Count(&h.Exhausted).Error; err != nil {
		log.Printf("[proxy-drain] 统计终态待办数量失败: %v", err)
		return h
	}
	var next []time.Time
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", false).Order("next_at asc").Limit(1).
		Pluck("next_at", &next).Error; err == nil && len(next) > 0 {
		t := next[0]
		h.NextAttemptAt = &t
	}
	var last model.ProxyDrainPending
	if err := s.DB.Select("last_err").
		Where("last_err <> ''").Order("updated_at desc").First(&last).Error; err == nil {
		h.LastErr = last.LastErr
	}
	return h
}

// retryPendingProxyDrains 重试所有到期的断流待办，返回仍在等待的数量。
//
// 每份待办套一个 closeProxiesTimeout 预算：frps 卡住时不能把整轮重试（以及
// 关闭阶段的优雅退出）一起拖死。预算用尽时剩余候选已经在 runProxyDrain 里
// 记成残留，会由本函数登记回退避队列。
func (s *Services) retryPendingProxyDrains(ctx context.Context) int {
	if s.DB == nil {
		// 没有数据库就没有待办表，连查都不必查（测试里存在这种构造路径）。
		return 0
	}
	if s.Frps == nil {
		// 未配置 frps 管理接口时重试一万次也不会成功；待办保留，等配置修好
		// 之后由新进程继续（这里不删，否则线索就没了）。
		return 0
	}
	now := time.Now()
	var rows []model.ProxyDrainPending
	if err := s.DB.Where("next_at <= ? AND exhausted = ?", now, false).
		Order("next_at asc").Limit(proxyDrainBatchSize).Find(&rows).Error; err != nil {
		log.Printf("[proxy-drain] 读取断流待办失败（本轮跳过）: %v", err)
		return 0
	}

	for i := range rows {
		if ctx.Err() != nil {
			break
		}
		row := rows[i]
		if !s.claimProxyDrain(&row, time.Now()) {
			continue
		}

		req := requestFromPending(row)
		intent, asDeleted := s.proxyDrainIntentState(row)
		switch intent {
		case proxyDrainIntentAbandoned:
			s.clearProxyDrainPending(req.userID, req.intent)
			log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号已被重新启用或再次禁用，状态版本已不是 %d），不再关闭其代理",
				req.userID, row.StatusGen)
			continue
		case proxyDrainIntentUnverifiable:
			// 领取时已经把 next_at 推到租期之后，这里什么都不做，下轮再判。
			continue
		}
		if asDeleted && !req.deleted {
			// 账号在禁用之后被删除：换成删号语义重试，避免继续拿已不存在的
			// users 行做状态版本复查。
			req.deleted = true
		}

		drainCtx, cancel := context.WithTimeout(ctx, closeProxiesTimeout)
		out := s.runProxyDrain(drainCtx, req)
		cancel()

		if out.abandoned {
			s.clearProxyDrainPending(req.userID, req.intent)
			log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号在断流过程中被重新启用），不再关闭其代理",
				req.userID)
			continue
		}
		if out.unknown || len(out.residual) > 0 {
			s.rescheduleProxyDrain(req, out)
			continue
		}
		s.clearProxyDrainPending(req.userID, req.intent)
		if out.closed > 0 {
			log.Printf("[proxy-drain] 用户 %d 的残留代理已补关（%d 条），待办已清除", req.userID, out.closed)
		}
	}

	var left int64
	if err := s.DB.Model(&model.ProxyDrainPending{}).Where("exhausted = ?", false).Count(&left).Error; err != nil {
		return 0
	}
	return int(left)
}

// ProxyDrainPendingCount 返回仍在重试的断流待办数量。
//
// 只供管理员/诊断入口与测试使用：这个数字长期非零意味着「有账号已经禁用或
// 删除，代理却还在转发」——从业务界面上完全看不出来，所以必须有一个能读的
// 观测点。
func (s *Services) ProxyDrainPendingCount() (int64, error) {
	var n int64
	err := s.DB.Model(&model.ProxyDrainPending{}).Where("exhausted = ?", false).Count(&n).Error
	return n, err
}

// StartProxyDrainWorker 常驻：接手上次进程遗留的断流待办，并持续按退避重试。
//
// 启动即跑一轮而不是等第一个 ticker：重启频繁的部署（滚动升级）里，待办
// 往往正是「上次没关完」的那批，让它们等一个轮询周期只是白白多跑一会儿流量。
//
// 协程总是启动，即使当前 frps 未配置：配置能力是静态的，但「有没有待办」
// 是运行期才知道的，让协程自己每轮判断，比在启动时猜一次更不容易漏。
// 返回值在协程退出时关闭，供关闭阶段等待（见 cmd/panel/main.go 的 workers）。
func (s *Services) StartProxyDrainWorker(ctx context.Context) <-chan struct{} {
	// 未配置 frps 管理接口是**静态**配置缺失，不是暂时故障：重试一万次也
	// 不会成功，进补偿队列只会让内存涨满并刷日志。但也不能静默——那意味着
	// 这个部署**根本没有断流手段**，删号/禁用之后已建立的流量会一直跑到
	// 客户端自己退出。所以启动时就明确告警一次（见缺陷 4）。
	if s.Frps == nil {
		log.Printf("[proxy-drain] 未配置 frps 管理接口：本部署无法主动断开已建立的代理流量，" +
			"删除/禁用账号后残留的转发只能等客户端自己退出。请配置 frps 管理地址以启用断流。")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(proxyDrainRetryInterval)
		defer ticker.Stop()

		if n := s.retryPendingProxyDrains(ctx); n > 0 {
			log.Printf("[proxy-drain] 启动时恢复了 %d 份待办的断流，将继续重试", n)
		}
		// 补偿队列里可能有上一个进程周期遗留的意图吗？没有——它在内存里。
		// 这里 flush 一次是为了覆盖「启动瞬间数据库刚恢复」的情况。
		s.flushProxyDrainFallback()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := s.retryPendingProxyDrains(ctx); n > 0 {
					log.Printf("[proxy-drain] 仍有 %d 份断流待办未完成，将在下个周期继续重试", n)
				}
				// 顺带尝试补写进程内补偿队列（数据库可能已经恢复）。
				// 放在同一个 ticker 里而不是另起一个：两者都是「每 30 秒检查
				// 一次断流相关状态」，分开只会多一个协程与一个定时器。
				s.flushProxyDrainFallback()
			}
		}
	}()
	return done
}
