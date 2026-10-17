package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// baselineLegacyKeep 是「无从确认归属的旧基线」在代理缺席后最多保留多久。
//
// 这些条目来自升级前（没有隧道标识）的数据，无法判断它属于哪条隧道：
// 留久了会让规模失控，丢太早又可能让同名重建的代理被重复计费。
// 一小时是个折中——超过这个时间还没再出现，就当它不会再回来。
const baselineLegacyKeep = time.Hour

// pruneDeadBaselines 从继承来的基线里剔除「已经不可能再用上」的条目。
//
//   - 隧道行已被删除：精确判断（基线带隧道 ID），立即剔除；
//   - 没有隧道标识的旧条目：无从判断，缺席超过 baselineLegacyKeep 才剔除。
//
// 只处理本轮**没出现**的名字：出现过的已经在上面覆盖成新值了。
// 查询失败时按「都还活着」处理——宁可多留一天，也不要把仍在使用的基线误删
// （误删的代价是那一轮把当天累计值重记一遍）。
func (s *Services) pruneDeadBaselines(nextStat map[string]trafficPair, seen map[string]bool, now time.Time) {
	ids := make([]uint, 0, len(nextStat))
	for name, prev := range nextStat {
		if seen[name] || prev.tunnelID == 0 {
			continue
		}
		ids = append(ids, prev.tunnelID)
	}

	alive := make(map[uint]bool, len(ids))
	if len(ids) > 0 {
		for start := 0; start < len(ids); start += inQueryBatch {
			end := start + inQueryBatch
			if end > len(ids) {
				end = len(ids)
			}
			var batch []uint
			if err := s.DB.Model(&model.Tunnel{}).
				Where("id IN ?", ids[start:end]).Pluck("id", &batch).Error; err != nil {
				for _, id := range ids[start:end] {
					alive[id] = true
				}
				continue
			}
			for _, id := range batch {
				alive[id] = true
			}
		}
	}

	for name, prev := range nextStat {
		if seen[name] {
			continue
		}
		if prev.tunnelID == 0 {
			if now.Sub(prev.seenAt) > baselineLegacyKeep {
				delete(nextStat, name)
			}
			continue
		}
		if !alive[prev.tunnelID] {
			delete(nextStat, name)
		}
	}
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
	// tunnelID 是这条代理对应的隧道行 ID，用于识别「同名隧道被删除后重建」。
	//
	// 代理名只由「用户 ID + 隧道名」组成：删了再建同名隧道，代理名一模一样，
	// 但 frps 侧的当日累计从 0 重新开始。没有这个标识时，采集会拿旧代理的
	// 基线去减新代理的计数——旧基线更大时走「跨零点」分支（把新计数整个记一遍），
	// 更小时则把新隧道前段的流量整段吃掉。两种情况都算错。
	tunnelID uint
	// unknown 表示这条基线来自**没有隧道标识的旧数据**（升级前的行）。
	//
	// 它可能是同名重建之前的旧值，无从判断，所以第一次用上它时不计增量
	// （见 collectTraffic）：最多损失一个采集周期的流量，好过把整天算错。
	unknown bool
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

// resetGenUnknown 是「这份基线对应的清零代次未知」的哨兵值。
//
// 真实代次只会在清零时从 0 往上加（见 AdminResetUserTraffic），-1 永远不可能
// 与它相等，因此 changedResetGens 一定把它判成「变过」：下一次采样到这个
// 用户时，这一轮增量被丢弃、代次随即被写成真实值，之后恢复正常。
//
// 为什么需要它：标记表是后续版本才加的，旧库升级上来时表里是空的。只把
// 「本轮采样到的用户」的代次写进去是不够的——升级时正好离线的用户不会被
// 采样，等它下次上线时基线还是升级前那份，而「没有标记」在
// changedResetGens 里会被当成「代次没变」，升级前（甚至停机期间）的清零
// 就识别不出来，清零前的流量被重新计入。哨兵把这个判断变成「未知」，
// 方向取保守的一侧：最多少记一轮，绝不重复计入。
const resetGenUnknown int64 = -1

// changedResetGens 返回「清零代次与上次提交时不同」的用户集合。
//
// 清零请求可能落在别的实例，本地的 pendingTrafficReset 根本看不到；代次存在
// 库里，采集侧据此判断这一轮增量是否横跨了清零点（横跨就丢弃，避免清零后
// 又把旧流量加回去）。
func (r *Runtime) changedResetGens(gens map[uint]int64) map[uint]bool {
	if len(gens) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out map[uint]bool
	for uid, gen := range gens {
		if prev, ok := r.lastResetGen[uid]; ok && prev != gen {
			if out == nil {
				out = make(map[uint]bool, 1)
			}
			out[uid] = true
		}
	}
	return out
}

// rememberResetGens 记录本轮成功提交时的清零代次。
func (r *Runtime) rememberResetGens(gens map[uint]int64) {
	if len(gens) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastResetGen == nil {
		r.lastResetGen = make(map[uint]int64, len(gens))
	}
	for uid, gen := range gens {
		r.lastResetGen[uid] = gen
	}
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

// StartTrafficCollector 启动后台采集协程，直到 ctx 结束。
func (s *Services) StartTrafficCollector(ctx context.Context) {
	interval := s.Cfg.TrafficPollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		// 退出时主动交还采集租约：正常重启不必等租期到期，新进程立刻能接手。
		defer s.releaseLease(leaseTrafficCollector)

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
				// 运行期设置跟着别的实例收敛：多实例共用一个库时，配置缓存
				// 只在本实例写入后才刷新，别的实例改了（保留端口、注册开关、
				// 配额规则…）这边会一直按旧值运行。
				s.ReloadSettingsIfChanged()
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

// leaseTrafficCollector 是「流量采集」的跨实例租约名。
const leaseTrafficCollector = "traffic-collector"

// trafficCollectLease 是采集租约的时长：必须长于一轮采集（含 frps 往返），
// 否则正常采集中的实例会被另一个实例抢走，两边同时记账。
const trafficCollectLease = 2 * time.Minute

// acquireLease 抢占（或续租）一个跨实例租约，返回本次的代次与是否持有。
//
// 抢占用条件更新：只有把 expires_at 推进成功的那一个实例，在租期内独占。
// 首次插入即成功；已存在时按「已过期」或「仍由我持有」续租——后者让持有者
// 每轮都能刷新租期，而不必等它过期。每次成功都推进 Gen（fencing token），
// 写库时在事务内核对它，过期持有者的写入会被拒。
//
// 插入失败不能一律当成「已被占用」：也可能是数据库真出错。此时走更新分支，
// 失败就返回 false（这一轮不采集），错误会在下一轮重试。
func (s *Services) acquireLease(name string, ttl time.Duration) (int64, bool) {
	now := time.Now()
	exp := now.Add(ttl)
	rec := model.RuntimeLease{Name: name, Holder: s.instanceID, ExpiresAt: exp, Gen: 1}
	if err := s.DB.Create(&rec).Error; err == nil {
		return rec.Gen, true
	}
	res := s.DB.Model(&model.RuntimeLease{}).
		Where("name = ? AND (expires_at < ? OR holder = ?)", name, now, s.instanceID).
		Updates(map[string]any{
			"holder":     s.instanceID,
			"expires_at": exp,
			"gen":        gorm.Expr("gen + 1"),
		})
	if res.Error != nil {
		log.Printf("[lease] 抢占租约 %s 失败: %v", name, res.Error)
		return 0, false
	}
	if res.RowsAffected != 1 {
		return 0, false
	}
	// 只有持有者能推进代次，所以这里读回的必然是自己刚写入的那个值。
	var lease model.RuntimeLease
	if err := s.DB.Where("name = ?", name).First(&lease).Error; err != nil {
		log.Printf("[lease] 读取租约 %s 代次失败: %v", name, err)
		return 0, false
	}
	return lease.Gen, true
}

// releaseLease 主动交还租约（仅当持有者是自己）。
//
// 正常退出时调用：新进程不必等租期到期就能接手采集。
// 崩溃退出时没人调用，租约自然过期——所以租期本身要短于「可接受的空窗」。
//
// 交还时也推进代次：任何仍拿着旧代次的在途写库都会因此被拒，
// 不会出现「已经交还了、旧进程又写进一笔」。
func (s *Services) releaseLease(name string) {
	res := s.DB.Model(&model.RuntimeLease{}).
		Where("name = ? AND holder = ?", name, s.instanceID).
		Updates(map[string]any{
			"expires_at": time.Now().Add(-time.Second),
			"gen":        gorm.Expr("gen + 1"),
		})
	if res.Error != nil {
		log.Printf("[lease] 交还租约 %s 失败: %v", name, res.Error)
	}
}

// collectTraffic 单次采集：拉取 frps 代理状态，计算增量并落库。
func (s *Services) collectTraffic(ctx context.Context) {
	// 多实例共用一个库时，每个进程都会启动采集器：各自读同一份 frps 累计值、
	// 各自算增量、各自累加——同一段流量会被记两遍。进程内的 Runtime.mu 管不到
	// 别的进程，所以用数据库里的租约把「谁采集」收敛成一个。
	if _, ok := s.acquireLease(leaseTrafficCollector, trafficCollectLease); !ok {
		if s.collectorOwned.Swap(false) {
			log.Printf("[traffic] 采集租约已转交其他实例，本实例暂停采集")
		}
		return
	}
	if !s.collectorOwned.Load() {
		// 每次「从未持有到持有」的转换都按库里的最新基线重建。
		//
		// 启动时虽然读过一次，但那时租约可能正被别的实例持有；它在随后的
		// 每一轮都在记账，等我们接手时内存里的基线已经落后好几轮——拿它算
		// 增量会把别人已经记过的流量再记一遍。重新读一次的成本只是一条查询。
		if !s.loadTrafficBaseline() {
			// 读不到基线就**不能**算「已持有」：否则下一轮会跳过重读，
			// 拿过期的内存基线算增量。交还租约，让下一轮重新走一遍接管流程。
			s.releaseLease(leaseTrafficCollector)
			s.collectorOwned.Store(false)
			log.Printf("[traffic] 取得采集租约时读取基线失败，已交还租约（下轮重试）")
			return
		}
		s.collectorOwned.Store(true)
		log.Printf("[traffic] 已取得采集租约，按库中基线继续采集")
	}

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
	// resetGens 是本轮采样时刻各用户的清零代次（见 flushTraffic 的条件更新）。
	var resetGens map[uint]int64
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
		// 记下本轮采样时刻的清零代次：落库时按它做条件更新，
		// 期间发生的清零（可能来自别的实例）会让这次增量写不进去。
		resetGens = make(map[uint]int64, len(users))
		for i := range users {
			resetGens[users[i].ID] = users[i].TrafficResetGen
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
	seenNames := make(map[string]bool, len(refs))

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

		cur := trafficPair{in: p.Status.TodayTrafficIn, out: p.Status.TodayTrafficOut,
			seenAt: now, tunnelID: t.ID}
		prev := lastStat[p.Name]
		// 同名隧道被删除后重建：代理名没变，但这是一条**新的**代理，
		// frps 侧的当日累计从 0 起算。拿旧基线相减会算错，这里按「从未见过」处理。
		if prev.tunnelID != 0 && prev.tunnelID != t.ID {
			prev = trafficPair{}
		}
		din, dout := cur.in-prev.in, cur.out-prev.out
		if prev.unknown {
			// 升级前的基线没有隧道标识，可能是同名重建之前的旧值。
			// 无从判断，就**不计这一轮增量**：直接把当前值当作新基线，
			// 最多损失一个采集周期，好过把整天的流量重记或少记。
			din, dout = 0, 0
		}
		// frps 的当日统计跨零点归零，此时当前值本身就是增量。
		if din < 0 {
			din = cur.in
		}
		if dout < 0 {
			dout = cur.out
		}
		nextStat[p.Name] = cur
		seenNames[p.Name] = true

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

	// 继承来的基线里，属于「隧道已被删除」的条目要清掉：它们永远不会再出现，
	// 留着只会让内存与基线表随「当天创建过的隧道数」增长，而不是当前隧道数。
	// 隧道仍然存在、只是暂时离线的（客户端关了）必须保留——那正是基线保留的意义。
	s.pruneDeadBaselines(nextStat, seenNames, now)

	s.Runtime.mu.Lock()
	seedBaseline := s.Runtime.baselineSeedPending
	s.Runtime.mu.Unlock()

	// 提交前先续租：一轮采集可能因为 frps 慢、库慢而超过租约时长，
	// 续不上就说明已被别的实例接手，本轮结果直接丢弃。
	//
	// 续租只缩小窗口，不构成完整 fencing——真正的校验在落库事务里：
	// 锁定租约行并核对代次（见 flushTraffic），检查与提交之间不再有缝隙。
	renewGen, ok := s.acquireLease(leaseTrafficCollector, trafficCollectLease)
	if !ok {
		// 丢掉本地持有标记：下一轮若重新抢到租约，必须走一遍「重新读基线」，
		// 否则会拿这份已经过时的 lastStat 继续算增量。
		s.collectorOwned.Store(false)
		log.Printf("[traffic] 采集租约已被其他实例接手，本轮结果丢弃（不写账）")
		return
	}
	// 与本实例上次提交时的清零代次比对：期间发生过清零的用户，这一轮增量
	// 横跨了清零点，直接丢弃（清零请求可能落在别的实例，本地标记看不到）。
	changed := s.Runtime.changedResetGens(resetGens)

	fence := trafficFence{
		leaseGen:     renewGen,
		resetGens:    resetGens,
		resetChanged: changed,
	}

	if err := s.flushTraffic(tunnelDeltas, userDeltas, tunnelOwner, nextStat, seedBaseline, fence); err != nil {
		if errors.Is(err, errLeaseLost) {
			s.collectorOwned.Store(false)
			log.Printf("[traffic] 租约在落库前被接管，本轮结果丢弃（不写账）")
			return
		}
		log.Printf("[traffic] 流量落库失败，本轮不推进采样基线（增量下轮补记）: %v", err)
	} else {
		s.Runtime.mu.Lock()
		s.Runtime.lastStat = nextStat
		seedReset := s.Runtime.resetMarkSeedPending
		s.Runtime.baselineSeedPending = false
		s.Runtime.resetMarkSeedPending = false
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
		if seedReset {
			// 本轮已经把采样到的清零代次写进标记表（见 flushTraffic），
			// 现在可以宣告「标记已初始化」，下一轮恢复正常计增量。
			if err := s.Settings.SetInternal(map[SettingKey]string{KeyTrafficResetMarkReady: "1"}); err != nil {
				log.Printf("[traffic] 写入清零代次迁移标记失败（下轮仍按首次处理）: %v", err)
			} else {
				log.Printf("[traffic] 清零代次标记已初始化，后续采集恢复正常计增量")
			}
		}
	}
	// 配额标记无论落库成败都要重算：它读的是库里**已有**的用量，
	// 与这一次写入是否成功无关。跳过它只会让超额状态更久不收敛。
	// 这里只处理「本轮有流量」的用户；到期用户与全量校准由 refreshGuardDue
	// 在采集之外执行（frps 挂掉时也必须继续跑）。
	s.refreshGuardForTraffic(userDeltas)
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
// errLeaseLost 表示落库时发现采集租约已被别的实例接手。
var errLeaseLost = errors.New("采集租约已被其他实例接手")

// trafficFence 是落库时的写库闸门。
//
// 零值表示「不参与校验」——只有测试会直接调用 flushTraffic；
// 生产路径一定带上租约代次与清零代次。
type trafficFence struct {
	// leaseGen 是本次采集持有的租约代次，0 表示不校验租约。
	leaseGen int64
	// resetGens 是采样时刻各用户的清零代次；resetChanged 是「自上次提交以来
	// 代次变过」的用户集合（清零可能来自别的实例，本地标记看不见）。
	resetGens    map[uint]int64
	resetChanged map[uint]bool
}

func (s *Services) flushTraffic(
	tunnelDeltas map[uint]*tunnelDelta,
	userDeltas map[uint]int64,
	tunnelOwner map[uint]uint,
	nextStat map[string]trafficPair,
	seed bool,
	// fence 是本轮采集的写库闸门；零值表示调用方不参与（测试直接调用）。
	fence trafficFence,
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

	// missedReset 记录「条件更新没命中」的用户：事务期间发生过清零。
	missedReset := make(map[uint]bool)
	// committedGens 是本次基线推进后应当记下的清零代次（落库 + 内存各一份）。
	committedGens := make(map[uint]int64, len(fence.resetGens))
	for uid, gen := range fence.resetGens {
		committedGens[uid] = gen
	}

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// fencing：在同一事务里锁住租约行并核对代次。
		//
		// 只在事务外「续租成功才写」是不够的：进程暂停或事务排队时租约仍可能
		// 在检查与提交之间被接手，两边于是各提交一份同一段增量。锁住这一行之后，
		// 接手的实例必须等本事务结束才能改它，而本事务在改之前就核对过代次。
		if fence.leaseGen != 0 {
			var lease model.RuntimeLease
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("name = ?", leaseTrafficCollector).First(&lease).Error; err != nil {
				return fmt.Errorf("%w: %v", errLeaseLost, err)
			}
			if lease.Holder != s.instanceID || lease.Gen != fence.leaseGen {
				return errLeaseLost
			}
		}

		// 在线时间**不受 seed 影响**：它记的是「这条隧道此刻在线」，
		// 与流量计费无关。seed 轮跳过的是增量（避免把当天累计重复计入），
		// 但用户接口靠 last_online_at 判断在线——首轮不写的话，迁移后的
		// 第一轮里所有隧道都会显示离线。
		for id, d := range tunnelDeltas {
			updates := map[string]any{}
			if d.online {
				updates["last_online_at"] = now
			}
			if !seed {
				if total := d.in + d.out; total > 0 {
					updates["traffic_used"] = gorm.Expr("traffic_used + ?", total)
				}
			}
			if len(updates) == 0 {
				continue
			}
			if err := tx.Model(&model.Tunnel{}).Where("id = ?", id).Updates(updates).Error; err != nil {
				return err
			}
		}

		if !seed {

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
				// 自上次提交以来被清零过（可能来自别的实例）：这一轮增量横跨了
				// 清零点，丢弃。库里的条件更新只能挡住「事务期间」的清零，
				// 挡不住「上一轮之后」的清零。
				if fence.resetChanged[uid] {
					continue
				}
				q := tx.Model(&model.User{}).Where("id = ?", uid)
				// 跨实例的清零协调：只在「清零代次仍等于本轮采样时读到的值」
				// 时累加。代次对不上说明期间发生过清零（可能来自别的实例），
				// 这笔增量属于清零前的流量，丢掉才对。
				if fence.resetGens != nil {
					if gen, ok := fence.resetGens[uid]; ok {
						q = q.Where("traffic_reset_gen = ?", gen)
					}
				}
				res := q.Update("traffic_used", gorm.Expr("traffic_used + ?", delta))
				if res.Error != nil {
					return res.Error
				}
				// RowsAffected = 0：期间被清零，这笔增量不计。
				if res.RowsAffected == 0 {
					missedReset[uid] = true
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

		// 期间被清零的用户（本地快照判定「变过」或条件更新没命中）：
		// 把库里**当前**的代次记为「本轮基线对应的代次」。
		// 记旧值的话，下一轮还会再判一次「变过」，白丢一轮清零后的真实流量。
		//
		// 播种轮（seed）跳过这一步：本轮只写基线、不计增量，此时把「代次
		// 未知」的哨兵改写成当前值，等于宣告「这份基线对应的就是当前代次」，
		// 而它恰恰可能是升级前那份——正好丢掉这条迁移要保住的信息。
		if !seed {
			for uid := range fence.resetChanged {
				missedReset[uid] = true
			}
		}
		for uid := range missedReset {
			var cur int64
			if err := tx.Model(&model.User{}).Where("id = ?", uid).
				Pluck("traffic_reset_gen", &cur).Error; err != nil {
				return err
			}
			committedGens[uid] = cur
		}
		// 代次与基线一起落库：重启/换手后据此判断「期间有没有被清零过」。
		if len(committedGens) > 0 {
			marks := make([]model.TrafficResetMark, 0, len(committedGens))
			for uid, gen := range committedGens {
				marks = append(marks, model.TrafficResetMark{UserID: uid, Gen: gen})
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"gen", "updated_at"}),
			}).Create(&marks).Error; err != nil {
				return err
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
				// 记下隧道行 ID：同名隧道删了重建时，靠它认出「这不是原来那条代理」。
				TunnelID: cur.tunnelID,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "proxy_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"date", "in_bytes", "out_bytes", "tunnel_id"}),
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
	// 记下本轮提交时的清零代次（含期间被清零、已改成当前值的用户），
	// 供下一轮判断「期间是否被清零过」。
	s.Runtime.rememberResetGens(committedGens)
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
	// 清零代次标记有自己的迁移状态：旧库有基线但没有标记表，首轮同样要
	// 保守跳过增量，否则「停机期间清零过」的那部分旧流量会被重新计入。
	seedReset := !s.Settings.Bool(KeyTrafficResetMarkReady)

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
		// TunnelID 为零说明这行是升级前写的（那时还没有这一列）：
		// 它可能是同名重建之前的旧值，标记为「无从判断」，首次使用时不计增量。
		m[r.ProxyName] = trafficPair{in: r.InBytes, out: r.OutBytes,
			seenAt: now, tunnelID: r.TunnelID, unknown: r.TunnelID == 0}
	}

	// 一并恢复「基线对应的清零代次」：没有它，重启/换手后无法判断
	// 「清零发生在上次采样之后、重启之前」，那段旧流量会被重新计入。
	var marks []model.TrafficResetMark
	if err := s.DB.Find(&marks).Error; err != nil {
		log.Printf("[traffic] 读取清零代次标记失败，将跳过采集以避免把清零前的流量加回来: %v", err)
		return false
	}
	gens := make(map[uint]int64, len(marks))
	for _, mk := range marks {
		gens[mk.UserID] = mk.Gen
	}
	// 首次启用标记表：除已有真实标记的用户外，其余全部记为「代次未知」。
	// 只依赖「本轮采样到的用户」会让升级时离线的用户在下次上线时被当成
	// 「代次没变」，见 resetGenUnknown 的说明。
	//
	// 播种失败必须**整轮放弃**，不能带着「一部分用户还没有标记」的状态继续：
	// 本轮采集成功后会落下迁移标记，而缺失的那些用户下次上线时仍会被当成
	// 「代次没变」，把清零前的流量加回来——正是这条迁移要防的事。
	// 返回 false 会让调用方跳过本轮并保留迁移标记，下一轮重新走这里重试。
	if seedReset {
		if err := s.seedUnknownResetGens(gens); err != nil {
			log.Printf("[traffic] 清零代次标记初始化失败，本轮跳过采集（下轮重试）: %v", err)
			return false
		}
	}

	s.Runtime.mu.Lock()
	s.Runtime.lastStat = m
	// 任一迁移标记缺失都按「首轮播种」处理：只写基线、不计增量。
	s.Runtime.baselineSeedPending = seed || seedReset
	s.Runtime.resetMarkSeedPending = seedReset
	s.Runtime.lastResetGen = gens
	s.Runtime.mu.Unlock()

	if len(m) > 0 {
		log.Printf("[traffic] 已恢复 %d 条采样基线（避免重启后重复计入当天流量）", len(m))
	}
	if seed {
		log.Printf("[traffic] 未发现基线迁移标记，第一轮采集只记录基线、不计流量增量")
	}
	if seedReset {
		log.Printf("[traffic] 未发现清零代次标记，第一轮采集只记录基线、不计流量增量")
	}
	return true
}

// seedUnknownResetGens 把库里所有用户都记为「清零代次未知」。
//
// 只在标记表首次启用（旧库升级）时调用一次，见 resetGenUnknown。
// 已有真实标记的用户不动：那份标记是上一版本采集器写的，可信。
//
// 哨兵必须**落库**：只放内存的话，控制面在那些用户上线之前重启一次，
// 这份「未知」就丢了，又回到「没有记录 = 代次没变」的老问题。
//
// 返回错误表示「还有用户没被标记」：调用方必须据此放弃本轮采集，否则
// 迁移会在标记不完整的情况下被宣告完成，而那些用户永远等不到哨兵。
func (s *Services) seedUnknownResetGens(gens map[uint]int64) error {
	var ids []uint
	if err := s.DB.Model(&model.User{}).Pluck("id", &ids).Error; err != nil {
		return fmt.Errorf("读取用户列表失败: %w", err)
	}
	marks := make([]model.TrafficResetMark, 0, len(ids))
	for _, id := range ids {
		if _, ok := gens[id]; ok {
			continue
		}
		gens[id] = resetGenUnknown
		marks = append(marks, model.TrafficResetMark{UserID: id, Gen: resetGenUnknown})
	}
	if len(marks) == 0 {
		return nil
	}
	// DoNothing：并发启动的另一个实例可能已经写过真实值，不能覆盖。
	// 分批写：用户量大时一次 INSERT 的绑定参数会超过驱动的上限。
	if err := s.DB.Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(&marks, 200).Error; err != nil {
		return fmt.Errorf("写入清零代次哨兵失败: %w", err)
	}
	log.Printf("[traffic] 已为 %d 个用户写入「清零代次未知」标记，下次采样时保守跳过一轮增量", len(marks))
	return nil
}
