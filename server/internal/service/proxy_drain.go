package service

// 本文件是「代理断流协调器」的对外入口与文档；实现拆在同目录的三个文件里。
//
// 从 frpc.go 拆出来的理由不是行数，而是**职责**。frpc.go 原先同时负责
// 「生成客户端配置」与「在运行期收回已建立的流量」两件事，而两者的失败
// 语义、调用时机、依赖都不同——前者是字符串拼装，后者要访问 frps 管理
// 接口、要拿用户锁、要按代理实例身份复查，且必须在事务提交之后执行。
// 混在一个文件里时，缺陷 1（删号不断流）与缺陷 9（按名字盲关）都属于
// 「这块逻辑没有被单独审视」的后果：断流代码散落在配置生成函数之间，
// 读的人不会意识到「账号已删除」是一条必须单独处理的路径。
//
// 一次断流按四个阶段推进，各自落在自己的文件里：
//
//	发现        本文件 runProxyDrain —— 一次批量列表，按前缀与时间水位筛候选
//	身份校验    proxy_drain_identity.go —— 实例身份快照与比对，防误关同名新实例
//	关闭        本文件 closeDrainedProxy —— 复查代次后逐条 CloseProxy
//	持久化残留  proxy_drain_retry.go —— 待办落库 + 后台重试器（frps 不可用后补偿）
//
// 对外只暴露三个入口，调用方按「账号还在」与「账号已删」二选一：
//
//	CloseUserProxies            —— 禁用/封禁：有状态代次可做跨实例见证
//	CloseDeletedUserProxies     —— 删号/注销：账号行已不存在，尽力关闭
//	closeUserProxiesAfterDelete —— 上面那个的带超时包装（两条删除路径共用）
//
// 锁序不变：本文件只取「该用户的锁」，不取任何全局锁。调用方在进入之前
// **必须**已经释放用户锁（见 admin_user_delete.go / user_delete.go 的说明）
// ——sync.Mutex 不可重入，持锁调用会自死锁。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// CloseUserProxies 关闭某用户在 frps 侧的所有已建立代理，实现「立即断流」。
//
// 禁用/封禁账号时调用：只更新阻断标记与清会话，拦得住**新**连接，却拦不住
// 已经建立的代理流——frps 与 frpc 之间的数据连接会一直转发。逐个关闭该用户
// 名下的代理，frps 会下线它们、断开已建立的数据连接。
//
// gen 是「这次禁用」对应的状态代次（见 bumpUserStatusGen）。断流要访问 frps
// 管理接口，最长可拖十几秒，而这段时间里用户可以已经被重新启用：客户端会
// 重连、建立新代理，甚至新代理就出现在下面这份列表里。此时继续关就不是
// 「断掉禁用前的流量」，而是把刚放行的人又踢下线。
//
// 复查与关闭都放在**该用户的锁**内，且粒度是一条代理：状态变更路径
// （启用/禁用/改配额）同样持这把锁，因此「确认代次未变」与「发出关闭请求」
// 之间不可能插进一次重新启用。只复查不放锁的话，两者之间仍有窗口——
// 检查通过、请求发出前用户被启用，那条新代理照样会被关掉。
//
// 锁的粒度是单条而不是整段：整段持锁会在 frps 变慢时把启用操作挡十几秒，
// 而用户点「启用」时最不该看到的就是长时间无响应。
//
// notAfter 是「本次禁用生效的时刻」。跨实例时锁与代次都挡不住最后一次竞态：
// 另一台实例上的启用可以正好插在查库之后、关闭请求到达 frps 之前。所以再
// 加一道基于 frps 自身数据的判据——代理的 lastStartAt：
//
//   - 新代理一定晚于 notAfter 启动（客户端重连会重新注册，frps 会刷新该时间），
//     这类直接跳过；
//   - 只有「禁用前就在跑、期间没有重新注册」的代理才关。
//
// 这是现有接口条件下能做到的最强保证。彻底原子需要 frps 关闭接口支持
// 「按版本条件关闭」，那是协议改动，不在本服务控制范围内。
//
// # 失败不再是一次性的
//
// 以前 frps 一不可用，这次断流就只留一行日志：已建立的数据流继续转发，
// 恢复之后也没有任何补偿。现在进入这里会**先落一条待办**（见
// proxy_drain_retry.go），本轮没关干净的代理由后台重试器按退避继续关，
// 直到关完才删待办。关闭失败依然不中断主流程：能关一个是一个。
func (s *Services) CloseUserProxies(ctx context.Context, userID uint, gen uint64, notAfter time.Time) {
	s.closeUserProxiesWithIntent(ctx, userID, gen, notAfter, "")
}

// closeUserProxiesWithIntent 执行已登记的断流意图；intent 非空时不会再次
// 创建待办，从而保持「状态事务 + 断流意图」的同一提交点。
func (s *Services) closeUserProxiesWithIntent(ctx context.Context, userID uint, gen uint64, notAfter time.Time, intent string) {
	s.drainProxies(ctx, proxyDrainRequest{
		userID:   userID,
		prefix:   FrpUserOf(userID) + ".",
		gen:      gen,
		notAfter: notAfter,
		intent:   intent,
	})
}

// closeProxiesTimeout 是断流访问 frps 管理接口的总超时。
//
// 断流要逐条复查 + 关闭，frps 变慢时可能拖十几秒。调用方（禁用、删除）都在
// 事务提交之后同步执行，必须有个上限，否则 frps 一卡住，管理端的禁用/删除
// 请求就一起卡住。后台重试器对**每个**待办也套用这个预算，于是「一轮重试」
// 的最坏时长 = 批量上限 × 该预算（见 proxy_drain_retry.go 的租期说明）。
const closeProxiesTimeout = 15 * time.Second

// CloseDeletedUserProxies 关闭**账号已被删除**的用户在 frps 侧残留的代理。
//
// 与 CloseUserProxies 的唯一差别是：没有状态版本可比。账号行已随删除事务
// 一起消失（users.state_version 无从读取），于是「这次断流是否已被别的实例
// 上的一次重新启用作废」这种判断**在事实上不成立**——账号都不存在了，不存在
// 「重新启用」这回事。这里如实退化成「按 user 前缀 + 代理实例身份尽力关闭」：
//
//   - 前缀 lt_u<ID>. 来自 frp 的 user 字段（见 FrpUserOf / ParseProxyName），
//     不依赖数据库，删号后依然可用；
//   - 实例身份（clientID / lastStartAt）来自 frps 自己的运行态，同样不依赖库。
//
// 两条判据都是尽力而为，不是原子保证：frps 管理接口不可用时就一条也关不掉。
// 这种情况必须记日志（含残留数量），留给运维排查或「客户端重连被拒」兜底，
// **绝不能静默跳过**——账号在面板里已经删除、代理却还在转发流量，这是最不
// 该出现的状态，而且从任何界面上都看不出来。
//
// 判不出实例身份的代理一律跳过（见 closeDrainedProxy 里的双空判据）：同名
// 代理可能已经是客户端重连后注册的新实例，关掉它等于让用户随机断流。
//
// 关不掉的那部分会留在落库待办里由后台继续重试（见 proxy_drain_retry.go）：
// 账号已删除，删除事务本身不可能因为这次失败而回滚，补偿只能放在这条路径上。
func (s *Services) CloseDeletedUserProxies(ctx context.Context, userID uint) {
	fence, incarnation, found, err := s.deletedDrainIntent(userID)
	if err != nil {
		// 读不出待办时**不能**当成「没有待办」重新登记：此刻 users 行已删，
		// 新登记的 incarnation 是空的，会把事务里记下的现场覆盖掉。原待办
		// 留给后台 worker，这一轮什么都不做。
		log.Printf("[proxy-drain] 读取已删账号 %d 的断流待办失败，保留原现场并跳过本次断流: %v", userID, err)
		return
	}
	if found && incarnation == "" {
		// 升级前遗留的待办没有账号标识。只有当该 ID 上确实存在一个已登记
		// 标识的账号时才可能误伤（删号后 ID 被复用）；此时交给人工确认。
		if inc, exists := s.currentIncarnation(userID); exists && inc != "" {
			log.Printf("[proxy-drain] 账号 %d 的断流待办缺少账号标识且该 ID 已被新账号占用，跳过自动断流，需人工确认", userID)
			return
		}
	}

	req := proxyDrainRequest{
		userID:  userID,
		prefix:  FrpUserOf(userID) + ".",
		deleted: true,
		// 复用删除事务里已经写好的那条待办。
		intent: fence,
	}
	if !found {
		// 没有待办（例如升级前删掉的账号）：只做一次尽力而为的即时断流，
		// 不为它新登记一条空标识的待办。
		req.noRegister = true
	}
	out := s.drainProxies(ctx, req)
	switch {
	case out.unknown:
		log.Printf("[service] 账号 %d 已删除，但拉取代理列表失败，残留代理数量无法确认（已记入待办由后台继续重试）；同时靠客户端重连被拒兜底，请人工排查",
			userID)
	case len(out.residual) > 0:
		log.Printf("[service] 账号 %d 已删除，但仍有 %d 个代理未能关闭（frps 管理接口不可用或实例身份不可判定），已记入待办由后台继续重试；同时靠客户端重连被拒兜底，请人工排查",
			userID, len(out.residual))
	}
}

// closeUserProxiesAfterDelete 是两条删除路径（管理员删除 / 自助注销）共用的
// 善后入口：包一层带超时的上下文，避免 frps 管理接口不可达时把删除请求拖住。
//
// 失败绝不影响删除结果：账号必须已经删掉，这里只是尽力收回已经建立的流量。
// 删除接口的返回值不变（仍然只反映数据库侧是否删成功），否则管理员会重试，
// 而重试只会得到「账号不存在」。
// deletedDrainIntent 读取删号事务留下的那条待办。
//
// 三种结果必须分开返回：
//   - found=false：确实没有待办（升级前删掉的账号），调用方可以做一次
//     「不落库」的尽力断流；
//   - err != nil：**读不出来**，现场不明，调用方必须放弃本轮而不是重新登记
//     ——此刻 users 行已删，新登记的 incarnation 是空的，会覆盖事务现场；
//   - found=true 且 incarnation 为空：升级前的遗留待办，无法核验身份，
//     交给人工确认。
func (s *Services) deletedDrainIntent(userID uint) (fence, incarnation string, found bool, err error) {
	if s.DB == nil {
		return "", "", false, errors.New("数据库未初始化")
	}
	var row model.ProxyDrainPending
	if qerr := s.DB.Select("fence", "incarnation").
		Where("user_id = ? AND deleted = ?", userID, true).
		First(&row).Error; qerr != nil {
		if errors.Is(qerr, gorm.ErrRecordNotFound) {
			return "", "", false, nil
		}
		return "", "", false, qerr
	}
	return row.Fence, row.Incarnation, true, nil
}

func (s *Services) closeUserProxiesAfterDelete(userID uint) {
	ctx, cancel := context.WithTimeout(context.Background(), closeProxiesTimeout)
	defer cancel()
	s.CloseDeletedUserProxies(ctx, userID)
}

// proxyDrainRequest 是一次断流请求的完整判据。
//
// 「关谁的代理」与「凭什么关」收成一个结构，是因为同一套判据要在三个时机
// 复用：立即断流（禁用/删号）、后台重试、以及重试时按落库待办重建。以前
// 判据散在函数参数与局部变量里，新增一条路径时很容易漏掉某一条——缺陷 1
// 正是「断流只做一次、失败就丢」的后果。
type proxyDrainRequest struct {
	userID   uint
	prefix   string
	gen      uint64
	notAfter time.Time
	deleted  bool
	// attempts 是这条意图此前已经重试失败的次数（立即路径为 0）。
	// 只用于算退避，不参与「关不关」的判定。
	attempts int
	// known 是从落库待办里恢复出来的「发现时观测到的实例身份快照」。
	//
	// 非空时重试**只盯着这些名字**，不再按前缀重新扫一遍全表：账号禁用/删除
	// 之后客户端可能已经重连并注册了同名的新实例，重新扫一遍会把新实例当成
	// 「残留」再关一次；而按快照对齐能确保重试关的仍是当初那批实例。
	known []proxyDrainTarget
	// intent 是本次落库待办的写入凭据（随机串）。
	//
	// 所有回写（改次数、删待办）都带上它：期间可能有更新的意图覆盖这一行
	// （账号再次被禁用、或删号路径写入自己那条），旧任务的回写不能把新意图
	// 改掉或删掉，否则那条真正该执行的断流就再也不会被重试。
	intent string
	// noRegister 表示这次断流只做「尽力而为的一次」，不允许新登记待办。
	//
	// 用于已经确认没有待办的删号路径（升级前遗留）：users 行已删，此时新登记
	// 的 incarnation 必然为空，而空标识的待办无法在 ID 复用时自证身份。
	noRegister bool
}

// proxyDrainOutcome 是一轮断流的结果。
//
// 三态必须分开，因为它们的收尾动作完全不同：
//
//	abandoned  —— 意图已作废（账号被重新启用）：删待办，不关任何代理
//	unknown    —— 没拿到可信的代理列表：残留数量无法确认，待办必须留着
//	residual   —— 明确知道还有哪些代理没关掉：记进待办，等下一轮
type proxyDrainOutcome struct {
	residual  []proxyDrainTarget
	unknown   bool
	abandoned bool
	closed    int
	lastErr   string
	// closedTargets 是本轮「发出关闭请求并收到成功」的那批代理的**关闭前**身份。
	//
	// 单独留下来是为了在整轮结束时统一做一次「关闭后复查」（见
	// verifyClosedProxies）：frps 的关闭接口只认名字，关闭请求返回成功并不
	// 等于「关掉的就是比对时那个实例」——从比对到 frps 执行之间，客户端可能
	// 已经用同名注册了新实例。
	closedTargets []proxyDrainTarget
}

// drainProxies 是断流的协调器入口：先落待办 → 跑一轮 → 按结果收尾。
//
// # 为什么先落待办再动手
//
// 落库与断流之间有一个无法消除的顺序问题：先断流后落库的话，frps 不可用
// （或进程就在这两步之间退出）时，待办根本不存在——补偿机会彻底丢失，
// 而这正是缺陷 1 的形态。先落待办则最坏只是留下一条「其实已经关干净了」的
// 待办，后台重试发现没有残留就把它删掉，代价只是一次空转。
//
// 返回值是本轮的结果（残留清单 / 列表是否可信 / 意图是否作废），供调用方
// 决定怎么记日志。注意它与「已关掉几条」不是一回事：失败的、身份判不出的
// 都算残留，而它们已经记进待办等下一轮。
func (s *Services) drainProxies(ctx context.Context, req proxyDrainRequest) proxyDrainOutcome {
	var out proxyDrainOutcome
	if s.Frps == nil {
		// 没有客户端也不代表代理已经关闭：保留待办，等待配置/依赖恢复后
		// 由 Worker 重试。否则上层会把空结果当成成功并删除唯一补偿线索。
		if req.intent == "" {
			req.intent = s.recordProxyDrainPending(req)
		}
		out.unknown = true
		out.lastErr = "frps 管理客户端未初始化，断流结果未知"
		log.Printf("[service] 未配置 frps 管理接口，用户 %d 的断流结果未知，已保留待办", req.userID)
		return out
	}
	if req.prefix == "" {
		req.prefix = FrpUserOf(req.userID) + "."
	}

	if req.intent == "" && !req.noRegister {
		req.intent = s.recordProxyDrainPending(req)
	}
	if req.intent == "" && !req.noRegister {
		// 落库失败（数据库整体不可用）。这时仍要继续断流——能关一个是一个，
		// 但「本次没关干净」将没有任何持久化补偿。
		//
		// 缺陷 4 的修复点：以前这里只记一行日志就完了，而日志会被滚动掉，
		// 重启后没有任何线索。现在把意图放进**进程内**补偿队列，由后台每
		// 30 秒尝试补写回库（见 proxy_drain_fallback.go）。它覆盖不了
		// 「进程紧接着崩溃」这种极端情况，但比「只剩一行日志」强得多。
		if s.drainFallback != nil {
			s.drainFallback.enqueue(req)
			log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败，已放入进程内补偿队列（数据库恢复后自动补写）", req.userID)
		} else {
			log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败且无补偿队列：本次若也没关干净，重启后将没有任何补偿机会", req.userID)
		}
	}

	out = s.runProxyDrain(ctx, req)
	switch {
	case out.abandoned:
		s.clearProxyDrainPending(req.userID, req.intent)
		log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号在断流期间被重新启用），不再关闭其代理", req.userID)
	case out.unknown || len(out.residual) > 0:
		s.rescheduleProxyDrain(req, out)
	default:
		s.clearProxyDrainPending(req.userID, req.intent)
		if out.closed > 0 {
			log.Printf("[proxy-drain] 用户 %d 的代理已全部关闭（%d 条），无残留", req.userID, out.closed)
		}
	}
	return out
}

// runProxyDrain 执行「发现 → 身份校验 → 关闭」三个阶段。
//
// 发现只拉**一次**批量列表（结果在同轮内按窗口复用，见
// proxy_drain_identity.go 的 proxySnapshotCache）：原先每关一条代理就重新
// 拉一次全量列表，N 条代理就是 N 次分页请求，frps 稍慢就会把 15 秒预算
// 耗在拉列表上，只关掉一部分。
func (s *Services) runProxyDrain(ctx context.Context, req proxyDrainRequest) proxyDrainOutcome {
	var out proxyDrainOutcome

	// 进程内代次先看一眼：本实例上刚发生的状态变更不必再花一次 frps 往返。
	// 「0」只能当作「没有信息」，不能当成「版本不符」（实例可能刚启动，
	// 也可能状态变更发生在别的实例上）。
	if !req.deleted {
		if cached := s.userStatusGen(req.userID); cached != 0 && cached != req.gen {
			log.Printf("[user] 用户 %d 的状态在断流开始前已变更，跳过本次断流", req.userID)
			out.abandoned = true
			return out
		}
	}

	cache := newProxySnapshotCache(s)
	// 有落库快照时按快照对齐，不再按前缀重扫：账号禁用/删除之后客户端可能
	// 已经重连并注册了同名的新实例，重扫会把新实例当成「残留」再关一次。
	// 快照里的每条仍然要过 cache.lookup + matches 的身份比对（见
	// closeDrainedProxy），所以「世界已经变了」的情况不会漏判。
	if len(req.known) > 0 {
		return s.closeDrainTargets(ctx, req, cache, req.known)
	}

	snap, err := cache.current(ctx)
	if err != nil {
		log.Printf("[user] 拉取代理列表失败，本次无法主动断流（新连接仍会被拒，已记入待办等 frps 恢复后重试）: %v", err)
		if req.deleted {
			log.Printf("[service] 账号 %d 已删除且代理列表拉取失败，残留代理数量无法确认，靠客户端重连被拒兜底", req.userID)
		}
		out.unknown = true
		out.lastErr = err.Error()
		return out
	}

	return s.closeDrainTargets(ctx, req, cache, snap.discoveryTargets(req.userID, req.prefix, req.notAfter))
}

// closeDrainTargets 逐条关闭候选代理，按阶段结果汇总。
//
// 与发现分开是因为它有**两个入口**：首次断流按前缀扫描得到的候选，以及
// 后台重试时按落库快照恢复的候选。两者的关闭判据完全一致，区别只在
// 「候选从哪来」——把关闭逻辑复制两份，是缺陷 1（两条路径各自维护、慢慢
// 走偏）的同一个教训。
func (s *Services) closeDrainTargets(ctx context.Context, req proxyDrainRequest, cache *proxySnapshotCache, candidates []proxyDrainTarget) proxyDrainOutcome {
	var out proxyDrainOutcome
	for i, t := range candidates {
		// 每处理一条前看一次截止：超时后继续发请求只会让调用方（禁用/删除
		// 请求）等更久，而剩下的代理已经记进待办，由后台接着关。
		if ctx.Err() != nil {
			out.residual = append(out.residual, candidates[i:]...)
			out.lastErr = "断流超出时间预算，剩余代理未处理"
			return out
		}
		step, errMsg := s.closeDrainedProxy(ctx, req, cache, t)
		switch step {
		case drainStepClosed:
			out.closed++
			out.closedTargets = append(out.closedTargets, t)
		case drainStepGone:
			// 代理已消失，或已经不是发现时那个实例（客户端重连后重新注册）。
			// 两种情况都**不是**残留：没有需要关的旧实例，也不该误关新的。
		case drainStepResidual:
			out.residual = append(out.residual, t)
			if out.lastErr == "" && errMsg != "" {
				out.lastErr = errMsg
			}
		case drainStepAbandoned:
			out.abandoned = true
			return out
		}
	}
	// 本轮一次关闭失败都没记下原因，但期间重拉列表失败过（沿用了旧快照继续
	// 判断）：把这个原因写进待办的 last_err。否则运维看到一行
	// 「残留 N 条、last_err 为空」，会以为是 frps 拒绝关闭，而实际是列表接口
	// 已经在抖——两者要查的东西完全不同。
	if out.lastErr == "" && cache.listErr != nil {
		out.lastErr = cache.listErr.Error()
	}

	// 关闭动作全部发完之后做一次统一复查（缺陷 3）。放在整轮末尾、只拉一次
	// 列表：逐条关闭后各拉一次会把请求数从 O(1) 拉回 O(N)，正是缺陷 5 修掉的
	// 形态（N 条代理 N+1 次分页抓取，frps 稍慢就耗光 15 秒预算）。
	return s.verifyClosedProxies(ctx, req, out)
}

// verifyClosedProxies 在关闭动作发出之后复查「同名代理有没有以另一个实例身份
// 重新出现」，把可能的误关如实记下来（缺陷 3）。
//
// # 为什么只能做到这一步
//
// frps v0.71 的管理接口没有「条件关闭」：CloseProxy 是
// DELETE /api/v2/proxies/{name}/del，只认名字，不认 clientID/lastStartAt。
// 因此「比对身份」与「frps 执行删除」之间必然存在时间差：
//
//	本实例比对通过（旧实例）→ 【另一台实例上客户端重连、同名代理注册成功】
//	→ 本实例发出 CloseProxy → 关掉的是**新**实例
//
// 这个窗口**无法消除**，只能缩小：关闭前用快照复查（closeDrainedProxy），
// 关闭后再取一次列表看结果。必须在注释与报告里说清楚这一点，而不是把它
// 当成「已经解决」——把不可能的事说成已修复，比不修更糟。
//
// # 两种复查结果的处理
//
//   - 同名代理以**不同身份**出现：可能是我们误关了新实例、客户端随即重连，
//     也可能是我们正确关了旧实例、客户端立刻重新注册。两种情况都无法区分，
//     但当前事实都是「这个账号的代理在跑」，所以记残留、留下明确日志与指标，
//     交给后台重试器下一轮按最新快照再关一次。
//   - 同名代理以**相同身份**仍在列表里：删除请求已经返回成功，而 frps 的
//     列表对刚删除的代理可能有短暂的可见性延迟；客户端重连也必然刷新
//     lastStartAt。所以这**不**记为残留（否则每轮都会空转、待办永远清不掉），
//     但必须留一行日志：真出现「删了还在」的怪状时，这是唯一的线索。
func (s *Services) verifyClosedProxies(ctx context.Context, req proxyDrainRequest, out proxyDrainOutcome) proxyDrainOutcome {
	if len(out.closedTargets) == 0 || ctx.Err() != nil {
		// 没有发出过关闭请求，或时间预算已经用完：不再额外发请求。
		// 预算用尽时剩余候选已记为残留，复查可以留给下一轮。
		return out
	}
	// 用**新的**快照缓存强制重拉：本轮那份可能还是关闭之前取的。
	fresh := newProxySnapshotCache(s)
	snap, err := fresh.current(ctx)
	if err != nil {
		// 关闭后复查失败时，关闭结果不完整可验证。保留原目标并标记
		// unknown/residual，避免上层清理待办后失去下一轮补偿线索。
		log.Printf("[user] 用户 %d 关闭 %d 个代理后无法复查实例身份（列表拉取失败），保留待办等待重试: %v",
			req.userID, len(out.closedTargets), err)
		out.unknown = true
		out.residual = append(out.residual, out.closedTargets...)
		if out.lastErr == "" {
			out.lastErr = err.Error()
		}
		return out
	}

	// sameIdentity 收集「关闭请求成功后仍在列表里、且身份没变」的代理名，
	// 用于合并成一条日志（见循环后的说明）。
	var sameIdentity []string
	for _, t := range out.closedTargets {
		cur, ok := snap.lookup(t.Name)
		if !ok {
			// 正常情况：关掉之后就不在列表里了。
			continue
		}
		reborn := targetOf(cur)
		if !reborn.identifiable() || t.matches(cur) {
			// 同一实例仍在列表里。合并成一条日志（见下方说明），不逐条刷。
			sameIdentity = append(sameIdentity, t.Name)
			continue
		}
		// 同名、不同实例：这是本模块最需要留痕的一种结果。
		msg := fmt.Sprintf("代理 %q 关闭后以另一个实例身份重新出现（clientID/lastStartAt 已变），"+
			"可能误关了新实例或客户端已重连", t.Name)
		log.Printf("[user] 用户 %d: %s；已记为残留，由后台按最新身份继续处理", req.userID, msg)
		s.countProxyDrainRaceSuspect()
		out.residual = append(out.residual, t)
		if out.lastErr == "" {
			out.lastErr = msg
		}
	}
	if len(sameIdentity) > 0 {
		// 只记一条：一批代理同时关掉时逐条打日志会把真正重要的那行淹没。
		//
		// 这条日志**不**把记录算成残留：删除请求已经返回成功，而 frps 列表对
		// 刚删除的代理存在短暂可见性延迟（客户端重连也会刷新 lastStartAt）。
		// 算成残留会让待办因为一个可观测性动作而永远清不掉，每轮空转。
		// 但如果它反复出现，说明「删了还在」是真实的，需要人工核对。
		log.Printf("[user] 用户 %d 的 %d 个代理在关闭请求成功后仍在列表中（实例身份相同）：%s；"+
			"可能是 frps 列表的可见性延迟，反复出现请人工核对 frps 与宿主机状态",
			req.userID, len(sameIdentity), strings.Join(sameIdentity, ", "))
	}
	return out
}

// ProxyDrainRaceHealth 是「关闭竞态疑似误伤」的可观测快照（缺陷 3）。
//
// 为什么必须暴露出来：这个竞态**无法消除**（frps 只支持按名字关闭），能做的
// 只有把窗口缩到一次往返并留下证据。而「用户说连上又断了」这类抱怨无法从
// 日志里区分原因——是断流误伤、是网络抖动、还是客户端自己重启。这个计数器
// 是唯一能把「疑似误伤」与其它原因分开的线索，因此它必须出现在管理端的系统
// 指标里，而不是只存在于进程内存。
//
// 与 AuditWriteHealth 一样是**实例级**指标：计数只在本进程内存，重启清零，
// 多实例部署时看到的是某一个实例的数字。字段里带 Instance 就是为了提醒读的
// 人别把它当成集群合计。
type ProxyDrainRaceHealth struct {
	// Instance 是产生这份计数的进程标识（重启会变）。
	Instance string `json:"instance,omitempty"`
	// Suspects 是「关闭请求成功后同名代理以另一个实例身份重新出现」的累计次数。
	//
	// 非零不等于一定误伤：也可能是我们正确关了旧实例、客户端立刻重新注册。
	// 但它意味着「有一条关闭动作的结果无法确认」，值得人工看一眼。
	Suspects uint64 `json:"suspects"`
}

// countProxyDrainRaceSuspect 记一次「关闭结果无法确认」的疑似误伤。
func (s *Services) countProxyDrainRaceSuspect() {
	if s == nil {
		return
	}
	s.drainRaceSuspects.Add(1)
}

// ProxyDrainRaceHealth 返回疑似误伤的累计次数，供管理端系统指标下发。
func (s *Services) ProxyDrainRaceHealth() ProxyDrainRaceHealth {
	if s == nil {
		return ProxyDrainRaceHealth{}
	}
	return ProxyDrainRaceHealth{
		Instance: s.instanceID,
		Suspects: uint64(s.drainRaceSuspects.Load()),
	}
}

// proxyDrainStep 是「处理一条候选代理」的结果。
type proxyDrainStep int

const (
	// drainStepClosed 已确认关闭。
	drainStepClosed proxyDrainStep = iota
	// drainStepGone 已不存在，或已是另一个实例：不是本次要关的对象。
	drainStepGone
	// drainStepResidual 本该关掉却没关成，要记入待办等下一轮。
	drainStepResidual
	// drainStepAbandoned 整轮作废（账号被重新启用），立即停止且不留待办。
	drainStepAbandoned
)

// closeDrainedProxy 在用户锁内复查身份并关闭一条代理。
//
// 复查与关闭必须同锁：状态变更路径持同一把锁，因此「确认代次未变」与
// 「发出关闭请求」之间不可能插进一次重新启用。锁只罩住单条代理而不是
// 整段，理由见 CloseUserProxies 的注释。
//
// 实例身份复查拿的是带窗口的快照（见 proxySnapshotCache）：快照过旧时
// 会重新拉一次列表，既避免「每条代理一次全量列表」，又不让身份判定的
// 窗口无限拉长。
func (s *Services) closeDrainedProxy(ctx context.Context, req proxyDrainRequest, cache *proxySnapshotCache, t proxyDrainTarget) (proxyDrainStep, string) {
	if !t.identifiable() {
		// clientID 与 lastStartAt **都**缺失时，这条代理没有任何可比的身份
		// 字段：按名字关等于赌「同名的一定还是同一个实例」。而客户端重连
		// （禁用被撤销、网络抖动、进程重启）会立刻用同一个名字重新注册，
		// 赌错就是把刚恢复的用户随机踢下线——用户侧只看到「连上又断」，
		// 从日志里也看不出是断流而不是网络问题。所以一律跳过并留日志：
		// 漏关一个代理最多多跑一会儿流量，误杀一条新连接是可见的故障。
		log.Printf("[service] 用户 %d 的代理 %q 缺少 clientID 与 lastStartAt，身份不可判定，跳过关闭，待下一轮/兜底",
			req.userID, t.Name)
		return drainStepResidual, ""
	}

	lock := s.userLock(req.userID)
	lock.Lock()
	defer lock.Unlock()

	// 账号已删除时跳过两段版本复查：users 行已随删除事务消失，既没有
	// 状态版本可比，也不存在「期间被重新启用」这回事。
	if !req.deleted {
		if cached := s.userStatusGen(req.userID); cached != 0 && cached != req.gen {
			log.Printf("[user] 用户 %d 的状态在断流过程中已变更，停止关闭剩余代理（避免误伤重新启用后的新代理）", req.userID)
			return drainStepAbandoned, ""
		}
		// 进程内代次只覆盖「本实例」。启用请求完全可能落在另一台实例上，
		// 而那台实例写下的状态版本，这里只能查库才看得到。
		// 查不到账号（已删除）或数据库暂时不可用时不据此中止：禁用本身
		// 已经生效，新连接会被拒，漏关的代理影响远小于误判。
		dbGen, err := s.userStateVersionFromDB(req.userID)
		if err == nil {
			if dbGen != req.gen {
				log.Printf("[user] 用户 %d 的状态在其他实例上已变更（版本 %d ≠ %d），停止关闭剩余代理",
					req.userID, dbGen, req.gen)
				return drainStepAbandoned, ""
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			// 状态无法确认时绝不能按旧版本继续 CloseProxy：另一实例可能
			// 已经重新启用并注册同名代理。保留待办，交给下一轮重试。
			log.Printf("[user] 用户 %d 的状态版本读取失败，跳过关闭并保留待办: %v", req.userID, err)
			return drainStepResidual, err.Error()
		}
		// ErrRecordNotFound 表示账号已删除，删除路径没有可比版本，
		// 继续依靠代理实例身份快照处理。
	}

	// 列表快照可能已经过时：同名代理在这里被重新注册后，直接按名称
	// CloseProxy 会把新实例误关。关闭前再取一次状态（按窗口复用，必要时
	// 重拉），并用 frps 返回的 clientID/lastStartAt 对齐同一个代理实例；
	// 无法确认身份时宁可漏关，也不误伤刚重新启用的连接。
	cur, ok, err := cache.lookup(ctx, t.Name)
	if err != nil {
		log.Printf("[user] 关闭代理 %q 前复查状态失败，跳过以避免误关新实例: %v", t.Name, err)
		return drainStepResidual, err.Error()
	}
	if !ok {
		log.Printf("[user] 代理 %q 已从 frps 列表消失，无需关闭", t.Name)
		return drainStepGone, ""
	}
	if !t.matches(cur) {
		log.Printf("[user] 代理 %q 的实例身份已变化，跳过关闭", t.Name)
		return drainStepGone, ""
	}

	// # 关闭动作本身的竞态（缺陷 3）：这里只能缩小窗口，不能消除
	//
	// 上面刚比对过实例身份，但 CloseProxy 是按**名字**关闭的（frps v0.71 的
	// DELETE /api/v2/proxies?name=<name> 没有「条件关闭」参数：它只认名字，
	// 不认 clientID/lastStartAt）。所以从这次比对到 frps 真正执行删除之间，
	// 仍然存在一个跨实例窗口：
	//
	//	本实例比对通过（旧实例）→ 【另一台实例上客户端重连、同名代理注册成功】
	//	→ 本实例发出 CloseProxy → 关掉的是**新**实例
	//
	// 这个窗口**无法消除**：只要关闭接口只认名字，就一定有「比对」与「删除」
	// 之间的时间差。这里能做的是把它缩小到一次往返——关闭前的快照复查紧贴
	// 关闭请求（同一把用户锁内、中间不插入任何其它 frps 调用），关闭之后再
	// 由 closeDrainTargets 末尾的 verifyClosedProxies 统一复查结果。
	//
	// 关闭后复查**刻意不放在这里**：逐条关闭后各拉一次全量列表就是缺陷 5 的
	// 形态（N 条代理 N+1 次分页抓取）。放在整轮末尾只拉一次，代价与收益都
	// 可接受（见 verifyClosedProxies）。
	if err := s.Frps.CloseProxy(ctx, t.Name); err != nil {
		log.Printf("[user] 关闭用户 %d 的代理 %q 失败: %v", req.userID, t.Name, err)
		return drainStepResidual, err.Error()
	}
	log.Printf("[user] 已关闭用户 %d 的代理 %q", req.userID, t.Name)
	return drainStepClosed, ""
}

// topLevelPrefix 判断代理名是否属于该用户前缀。
//
// 单独一个函数而不是内联 strings.HasPrefix：前缀比较是最外层的过滤条件，
// 它写错了的后果是「关别人的代理」——必须一眼能看出比较的到底是什么。
func topLevelPrefix(name, prefix string) bool {
	return strings.HasPrefix(name, prefix)
}
