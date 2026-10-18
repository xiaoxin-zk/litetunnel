package service

// 本文件是「代理断流协调器」：把已经建立的 frps 代理关掉。
//
// 从 frpc.go 拆出来的理由不是行数，而是**职责**。frpc.go 原先同时负责
// 「生成客户端配置」与「在运行期收回已建立的流量」两件事，而两者的失败
// 语义、调用时机、依赖都不同——前者是字符串拼装，后者要访问 frps 管理
// 接口、要拿用户锁、要按代理实例身份复查，且必须在事务提交之后执行。
// 混在一个文件里时，缺陷 1（删号不断流）与缺陷 9（按名字盲关）都属于
// 「这块逻辑没有被单独审视」的后果：断流代码散落在配置生成函数之间，
// 读的人不会意识到「账号已删除」是一条必须单独处理的路径。
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
	"log"
	"strings"
	"time"
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
// 关闭失败不中断：能关一个是一个，失败的由「客户端重连被拒」兜底。
func (s *Services) CloseUserProxies(ctx context.Context, userID uint, gen uint64, notAfter time.Time) {
	s.closeUserProxies(ctx, userID, gen, notAfter, false)
}

// closeProxiesTimeout 是断流访问 frps 管理接口的总超时。
//
// 断流要逐条拉列表 + 复查 + 关闭，frps 变慢时可能拖十几秒。调用方（禁用、
// 删除）都在事务提交之后同步执行，必须有个上限，否则 frps 一卡住，管理端
// 的禁用/删除请求就一起卡住。
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
// 判不出实例身份的代理一律跳过（见 closeUserProxies 里的双空判据）：同名
// 代理可能已经是客户端重连后注册的新实例，关掉它等于让用户随机断流。
func (s *Services) CloseDeletedUserProxies(ctx context.Context, userID uint) {
	if n := s.closeUserProxies(ctx, userID, 0, time.Time{}, true); n > 0 {
		log.Printf("[service] 账号 %d 已删除，但仍有 %d 个代理未能关闭（frps 管理接口不可用或实例身份不可判定），请人工排查",
			userID, n)
	}
}

// closeUserProxiesAfterDelete 是两条删除路径（管理员删除 / 自助注销）共用的
// 善后入口：包一层带超时的上下文，避免 frps 管理接口不可达时把删除请求拖住。
//
// 失败绝不影响删除结果：账号必须已经删掉，这里只是尽力收回已经建立的流量。
// 删除接口的返回值不变（仍然只反映数据库侧是否删成功），否则管理员会重试，
// 而重试只会得到「账号不存在」。
func (s *Services) closeUserProxiesAfterDelete(userID uint) {
	ctx, cancel := context.WithTimeout(context.Background(), closeProxiesTimeout)
	defer cancel()
	s.CloseDeletedUserProxies(ctx, userID)
}

// closeUserProxies 是断流的实现。
//
// deleted 为 true 表示账号行已经不存在：没有任何状态版本可比，只能按前缀与
// 实例身份尽力关闭（见 CloseDeletedUserProxies）。返回值为「本该关掉、但没
// 能确认关掉」的代理数量，供调用方按残留数量记日志。
func (s *Services) closeUserProxies(ctx context.Context, userID uint, gen uint64, notAfter time.Time, deleted bool) int {
	if s.Frps == nil {
		// 未配置 frps 管理接口时无从断流。不 panic 也不上抛错误：此刻账号已经
		// 删掉/禁用掉了，一个可选依赖缺失不该让主流程失败。
		log.Printf("[service] 未配置 frps 管理接口，无法关闭用户 %d 的已建立代理", userID)
		return 0
	}
	// gen 来自 users.state_version（见 AdminSetUserStatus），是跨实例的版本。
	// 内存里可能还没有这个用户（刚启动，或状态变更发生在别的实例上），
	// 所以「0」只能当作「没有信息」，不能当成「版本不符」。
	//
	// 账号已删除时跳过这段：没有版本可比，而且删号本身就是最新状态，
	// 不存在「期间被重新启用」这种情况。
	if !deleted {
		if cached := s.userStatusGen(userID); cached != 0 && cached != gen {
			log.Printf("[user] 用户 %d 的状态在断流开始前已变更，跳过本次断流", userID)
			return 0
		}
	}
	prefix := FrpUserOf(userID) + "."
	proxies, err := s.Frps.ListProxies(ctx)
	if err != nil {
		log.Printf("[user] 拉取代理列表失败，本次无法主动断流（新连接仍会被拒）: %v", err)
		if deleted {
			log.Printf("[service] 账号 %d 已删除且代理列表拉取失败，残留代理数量无法确认，靠客户端重连被拒兜底", userID)
		}
		return 0
	}
	residual := 0
	for _, p := range proxies {
		if !strings.HasPrefix(p.Name, prefix) {
			continue
		}
		// 代理在禁用生效之后才启动 = 重新启用后的新连接（或被客户端重连
		// 重新注册过），关掉它就等于把刚放行的人又踢下线。
		// lastStartAt 缺失（老版本 frps）时不作判断，退回只靠代次与锁。
		if p.Status.LastStartAt > 0 && !notAfter.IsZero() {
			if startedAt := time.Unix(p.Status.LastStartAt, 0); startedAt.After(notAfter) {
				log.Printf("[user] 用户 %d 的代理 %q 在禁用之后才启动（%s），跳过关闭",
					userID, p.Name, startedAt.Format(time.RFC3339))
				continue
			}
		}
		// 复查代次与关闭动作在同一把用户锁内完成：列表是几秒前拉的，
		// 期间状态可能已经翻转，而这个窗口必须以锁关闭，不能只靠一次读。
		lock := s.userLock(userID)
		lock.Lock()
		// 账号已删除时跳过两段版本复查：users 行已随删除事务消失，既没有
		// 状态版本可比，也不存在「期间被重新启用」这回事（见 CloseDeletedUserProxies）。
		if !deleted {
			if cached := s.userStatusGen(userID); cached != 0 && cached != gen {
				lock.Unlock()
				log.Printf("[user] 用户 %d 的状态在断流过程中已变更，停止关闭剩余代理（避免误伤重新启用后的新代理）", userID)
				return residual
			}
			// 进程内代次只覆盖「本实例」。启用请求完全可能落在另一台实例上，
			// 而那台实例写下的状态版本，这里只能查库才看得到。
			// 查不到账号（已删除）或数据库暂时不可用时不据此中止：禁用本身
			// 已经生效，新连接会被拒，漏关的代理影响远小于误判。
			if dbGen, err := s.userStateVersionFromDB(userID); err == nil && dbGen != gen {
				lock.Unlock()
				log.Printf("[user] 用户 %d 的状态在其他实例上已变更（版本 %d ≠ %d），停止关闭剩余代理",
					userID, dbGen, gen)
				return residual
			}
		}
		// 列表快照可能已经过时：同名代理在这里被重新注册后，直接按名称
		// CloseProxy 会把新实例误关。关闭前再取一次状态，并用 frps 返回的
		// clientID/lastStartAt 对齐同一个代理实例；无法确认身份时宁可漏关，
		// 也不误伤刚重新启用的连接。
		//
		// clientID 与 lastStartAt **都**缺失时，这条代理没有任何可比的身份
		// 字段：按名字关等于赌「同名的一定还是同一个实例」。而客户端重连
		// （禁用被撤销、网络抖动、进程重启）会立刻用同一个名字重新注册，
		// 赌错就是把刚恢复的用户随机踢下线——用户侧只看到「连上又断」，
		// 从日志里也看不出是断流而不是网络问题。所以这种情况一律跳过并留日志：
		// 漏关一个代理最多多跑一会儿流量，误杀一条新连接是可见的故障。
		if p.ClientID == "" && p.Status.LastStartAt <= 0 {
			lock.Unlock()
			log.Printf("[service] 用户 %d 的代理 %q 缺少 clientID 与 lastStartAt，身份不可判定，跳过关闭，待下一轮/兜底", userID, p.Name)
			residual++
			continue
		}
		current, listErr := s.Frps.ListProxies(ctx)
		if listErr != nil {
			lock.Unlock()
			log.Printf("[user] 关闭代理 %q 前复查状态失败，跳过以避免误关新实例: %v", p.Name, listErr)
			residual++
			continue
		}
		matched := false
		for _, q := range current {
			if q.Name != p.Name {
				continue
			}
			if p.ClientID != "" && q.ClientID != p.ClientID {
				continue
			}
			if p.Status.LastStartAt > 0 && q.Status.LastStartAt != p.Status.LastStartAt {
				continue
			}
			matched = true
			break
		}
		if !matched {
			lock.Unlock()
			log.Printf("[user] 代理 %q 的实例身份已变化或已消失，跳过关闭", p.Name)
			residual++
			continue
		}
		err := s.Frps.CloseProxy(ctx, p.Name)
		lock.Unlock()
		if err != nil {
			log.Printf("[user] 关闭用户 %d 的代理 %q 失败: %v", userID, p.Name, err)
			residual++
			continue
		}
		log.Printf("[user] 已关闭用户 %d 的代理 %q", userID, p.Name)
	}
	return residual
}
