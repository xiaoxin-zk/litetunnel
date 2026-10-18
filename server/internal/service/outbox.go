package service

// 本文件是「事务 outbox」：把「业务数据已改、副作用还没做」这件事，与业务
// 变更写进**同一个数据库事务**。
//
// # 它修的是什么故障
//
// 删除隧道、停用隧道、删除账号这三个动作都是「先改数据库、再动外部世界」：
//
//	DeleteTunnel     ：DELETE lt_tunnels          → 收回防火墙规则
//	setTunnelStatus  ：UPDATE lt_tunnels.status   → 收回/放行防火墙规则
//	accountPurgeTx   ：DELETE users 及其关联数据   → 断流 + 收回全部端口规则
//
// 以前的写法是「事务提交之后再登记待办」（见 account_lifecycle.go 的
// purgeAccountAfterCommit 与 tunnel.go 里提交后的 applyPortIntent）。于是存在
// 一个**提交后崩溃窗口**：
//
//	事务提交（数据已删）→ 【进程被 kill / OOM / 断电 / 部署滚动重启】→ 善后从未执行
//
// 落在这个窗口里的后果是不对称的、而且从界面上完全看不出来：
//
//   - 隧道记录没了，宿主机上的放行规则还在——端口对外开着，面板上没有任何
//     一条隧道与它对应，启动时的规则对齐又刻意只补放行、不回收，于是这条
//     规则会一直留到有人手工清；
//   - 账号删了，frps 上已建立的数据流还在转发——frps 与 frpc 之间的数据连接
//     不经过任何准入判断，会一直跑到客户端自己退出，而账号已经不在列表里，
//     没有任何页面提示「它的流量还活着」。
//
// 这类故障无法靠「把善后写得更仔细」消除：窗口不在代码里，而在两次系统调用
// 之间。唯一的修法是让「数据已改」与「待办已存在」成为**同一个原子事实**——
// 要么都在，要么都不在。这就是 outbox：待办行与业务变更同事务写入，事务提交
// 即代表待办一定存在；进程在任何时刻死掉，重启后后台 worker 都能捡到那行
// 待办继续执行。
//
// # 为什么不新增一张 outbox 表
//
// 「同事务落库」是要求，不是形式。仓库里已经有两张**按意图收敛**的待办表，
// 它们本身就是 outbox 载体：
//
//	lt_firewall_pending     ：按端口一条，带单调代次 generation，用于防火墙收敛
//	lt_proxy_drain_pending  ：按用户一条，带围栏令牌 fence，用于断流收敛
//
// 再建一张统一 outbox 表，就得把「按端口收敛」「按用户收敛」「代次/围栏比较」
// 这些语义在两张表之间复制一遍，并且出现两个真相来源：worker 既要读 outbox
// 又要读原待办表，谁先谁后、哪张算数都得再定义一次。收敛语义正是这两张表
// 存在的原因（同一个端口/用户只可能有一个有效意图，后来的覆盖先前的），
// 复制一份只会让它们分叉。
//
// 所以这里复用的是「载体」，新增的是「写入口」：下面这些 Tx 版本的函数只
// 接受调用方的 *gorm.DB 事务句柄，绝不自己开事务（SQLite 是单写者，在已打开
// 的事务里再开一个会直接把自己锁死），并且**任何一步失败都返回错误**，由调用
// 方让整个事务回滚。
//
// # 事务边界画在哪
//
// 边界画在「业务数据变更的最后一条语句」与「待办行写入」之间不留空隙：
//
//	tx: 锁用户行 → 删隧道/改状态 → 写断流意图 → 写防火墙意图 → 删 users 行 → COMMIT
//	                                                                    ↑ 提交点
//	提交后（非事务）：立刻尝试执行一次（能成功就当场收尾，失败留给 worker）
//
// 提交点之前的一切失败都会回滚，不会留下「数据改了但没待办」；提交点之后
// 进程死掉，待办已经在库里，worker 重启即接手。提交后的「立刻执行」只是
// 缩短「待办存在但尚未执行」的时间，不是正确性的来源——这一点很关键：
// 以前它正是唯一的来源，所以它一失败就等于补偿彻底丢失。

import (
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TunnelMutationResult 是「隧道状态变更类接口」的结构化结果。
//
// # 为什么不再只返回 error
//
// 这类接口有两段彼此独立的结果：数据库有没有改成功、防火墙规则有没有跟上。
// 用单一 error 表达时只能二选一，而真实情况恰恰是「数据库已改、规则待处理」
// ——把它压成一个 error，调用方要么当成失败（管理员会重试删除，得到「隧道
// 不存在」，以为系统坏了），要么当成成功（界面上什么都不提示，用户带着
// 「端口已经关了」的错误认知去排查）。两种都是假修复。
//
// 所以：error 只表示「什么都没变」（数据库没改成功，接口应当报错）；
// 数据库改成功但规则没跟上时返回 nil error + FirewallPending/Warning，
// 由 handler 透给前端，界面上明确写「数据库已更新、规则待处理」。
type TunnelMutationResult struct {
	// DBUpdated 表示数据库变更已经提交（此后重试同一请求只会得到「不存在」）。
	DBUpdated bool `json:"db_updated"`
	// FirewallPending 表示防火墙规则还没跟上，已进入持久化重试队列，
	// 后台会继续尝试；为 false 且 Warning 为空表示规则也已到位。
	FirewallPending bool `json:"firewall_pending"`
	// Warning 是给用户看的中文说明（为什么没跟上、接下来会发生什么）。
	Warning string `json:"warning,omitempty"`
}

// portIntent 是一条「事务内已登记、提交后待执行」的防火墙端口意图。
//
// gen 必须一路带到执行阶段：执行成功后要按代次撤销这条待办（dropPending），
// 而期间可能有更新的意图（用户刚停用又启用）写入同端口——不带代次的无条件
// 删除会把那条新意图一起删掉，重启后它就再也不会被重试。
type portIntent struct {
	port  int
	proto string
	open  bool
	gen   int64
}

// nextFirewallGenTx 在调用方的事务内取下一个防火墙待办代次。
//
// 与 nextFirewallGen 的区别只有一个：不自己开事务。这个区别是硬性的——
// SQLite 连接池被限制成单连接（见 store.Open），在已打开的事务里再开一个
// 事务会永久等待自己持有的那条连接，表现为整个请求挂死而不是报错。
//
// 取号必须与待办写入同事务：代次是「谁更新」的判据，若先取号、事务回滚、
// 另一个请求取走同一个号并写入，两次意图就会撞在同一个代次上，>= 条件
// 无法区分先后，旧意图的回写可能顶掉新意图。
func nextFirewallGenTx(tx *gorm.DB) (int64, error) {
	var seq model.FirewallSeq
	// 锁住序列行：多实例共用一个库时，两个实例同时取号会读到同一个 Next，
	// 各自写回 Next+1，其中一个的号被覆盖——两条不同意图拿到相同代次。
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&seq, 1).Error; err != nil {
		return 0, err
	}
	if err := tx.Model(&model.FirewallSeq{}).Where("id = ?", 1).
		Update("next", seq.Next+1).Error; err != nil {
		return 0, err
	}
	return seq.Next, nil
}

// firewallIntentTx 在调用方的事务内登记一条防火墙端口意图，返回它的代次。
//
// # 为什么失败必须上抛
//
// 调用方此刻已经把业务数据改了（隧道删了/状态改了/账号删了）。若这里把
// 写库失败吞掉（像 persistPending 那样只记日志），事务照常提交，于是又回到
// 「数据已改、待办不存在」——正是本文件开头描述的那个窗口，只不过这次的
// 原因从「进程崩溃」变成了「写待办失败」。所以这里返回 error，调用方必须
// 让它把整个事务回滚：宁可这次删除/停用整体失败让用户重试，也不能留下一个
// 无人知晓的孤儿规则。
//
// 条件写与 persistPending 完全一致（见那里的注释）：代次更高才覆盖，同代次
// 只允许重试次数不倒退。事务内登记的都是**新意图**（代次最高），正常情况下
// 一定覆盖；保留条件是为了不破坏「落库在锁外、旧写回可能晚于新意图」这一
// 既有不变式。
func firewallIntentTx(tx *gorm.DB, port int, proto string, open bool) (int64, error) {
	if port <= 0 {
		return 0, nil
	}
	gen, err := nextFirewallGenTx(tx)
	if err != nil {
		return 0, fmt.Errorf("取防火墙待办代次失败（端口 %d）: %w", port, err)
	}
	rec := model.FirewallPending{
		Port:       port,
		Proto:      proto,
		Open:       open,
		Generation: gen,
	}
	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"proto", "open", "attempts", "exhausted", "generation", "last_err",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr("excluded.generation > lt_firewall_pending.generation OR (excluded.generation = lt_firewall_pending.generation AND excluded.attempts >= lt_firewall_pending.attempts)"),
		}},
	}).Create(&rec).Error; err != nil {
		return 0, fmt.Errorf("防火墙意图落库失败（端口 %d），已回滚本次变更: %w", port, err)
	}
	return gen, nil
}

// adoptPendingIntent 把事务内登记的意图同步到进程内队列。
//
// 必须**在事务提交之后**调用，不能在事务里调用：事务可能回滚，而内存里的
// 待办没有回滚机制——那样会留下一条「内存说有、库里没有」的幽灵待办，
// 重启后凭空消失，比没有更糟（管理页会显示一条永远清不掉的待处理项）。
//
// 代次比较沿用 markFirewallPending 的规则：只有更新的代次才能覆盖内存里的
// 旧意图，避免「事务提交晚于另一个请求的登记」时用旧意图顶掉新意图。
func (s *Services) adoptPendingIntent(port int, proto string, open bool, gen int64) {
	if port <= 0 || gen <= 0 {
		return
	}
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	prev, exists := s.fwPending[port]
	if exists && gen <= prev.gen {
		return
	}
	attempts := 0
	// 意图没变（同协议、同动作）时继承重试次数：这与 markFirewallPending
	// 的规则一致，否则一次「停用 → 启用 → 停用」就会把预算刷满，
	// 永久性失败（端口在保护列表里）永远到不了终态。
	if exists && prev.open == open && prev.proto == proto {
		attempts = prev.attempts
	}
	s.fwPending[port] = pendingFW{open: open, proto: proto, attempts: attempts, gen: gen}
}

// executePortIntentsAfterCommit 在事务提交后立刻尝试执行已登记的端口意图。
//
// 它只是「缩短待办存在但尚未执行」的窗口，不承担正确性：失败会进重试队列，
// 由 firewall_reconciler.go 的后台 worker 继续处理。返回值里的 warnings 是
// 需要让用户看见的中文说明（handler 会把它透到前端），pending 是仍未收尾的
// 端口数。
//
// # fatal 与 pending 的区别（调用方必须分清）
//
// 两者都表示「规则没到位」，但后续命运完全不同：
//
//   - pending > 0 且 fatal == nil：意图**已经**进了持久化重试队列，后台会
//     继续尝试。此时接口应当报成功 + 一句「规则待处理」的提示——把它当失败
//     报错，会让用户/管理员重试一个已经成功的操作（删隧道会得到「不存在」）。
//   - fatal != nil：连队列都没进去（队列满 / 数据库不可用）。这才是真正需要
//     如实报错的情况——没有任何人会再尝试这条规则，只能靠人处理。
//
// 以前这两者被压成同一个 error 判断（只在上层检查 ErrFirewallQueueFull /
// ErrFirewallQueueUnavailable），所以启用路径能正确区分、删除路径干脆不看。
// 现在统一由这里给出，三条路径用同一套语义。
//
// 执行成功后按代次撤销待办（dropPending）：这条意图已经完成，留着只会让
// 后台每轮空转一次。
func (s *Services) executePortIntentsAfterCommit(intents []portIntent) (pending int, fatal error, warnings []string) {
	for _, it := range intents {
		if it.port <= 0 {
			continue
		}
		// 先把事务里登记的意图放回内存队列：这样即便下面的 applyPortIntent
		// 失败，待办也已经是「内存 + 数据库」双份，管理页立刻可见。
		s.adoptPendingIntent(it.port, it.proto, it.open, it.gen)

		// 这里不关心 acted（是否真的动了手）：成功路径上两种情况都要撤销这条
		// 意图——acted 表示规则已到位，!acted 表示意图已过时或状态读不出来
		// （后者 applyPortIntent 内部已用更新的代次重新登记，按本次代次删除
		// 不会误删那条新待办）。所以只用 _ 接住，避免误以为它参与判断。
		_, err := s.applyPortIntent(it.port, it.proto, it.open)
		if err == nil {
			s.dropPending(it.port, it.gen)
			continue
		}

		pending++
		msg := fmt.Sprintf("端口 %d/%s %s失败，已进入重试队列：%v",
			it.port, it.proto, actionName(it.open), err)
		log.Printf("[outbox] %s", msg)
		warnings = append(warnings, msg)
		// 只有「入队也失败」才算致命：applyPortIntent 把 markFirewallPending
		// 的错误用 %w 包在返回里（见 applyPortIntentLocked），errors.Is 能识别。
		if errors.Is(err, ErrFirewallQueueFull) || errors.Is(err, ErrFirewallQueueUnavailable) {
			if fatal == nil {
				fatal = err
			}
		}
	}
	return pending, fatal, warnings
}

// firewallPendingWarning 把执行结果收成给用户看的一句话。
//
// 单独一个函数是因为用户侧与管理侧要显示同一句话：两处各拼一份，先改的那处
// 一定会漏掉另一处，界面上就会出现两种说法解释同一件事。
func firewallPendingWarning(warnings []string, count int) string {
	if count <= 0 {
		return ""
	}
	if len(warnings) > 0 {
		return "数据库已更新，但防火墙规则尚未生效（" + warnings[0] + "）；后台会自动重试，无需重复操作"
	}
	return "数据库已更新，但防火墙规则尚未生效；后台会自动重试，无需重复操作"
}

// tunnelMutationResult 由「数据库已改、善后已尝试」的结果组装结构化返回值。
//
// 单独抽出来是为了让三条路径（删除隧道、停用隧道、启用隧道）用同一套措辞：
// 前面 DBUpdated=true 是调用点的事实，后面 pending/warnings 来自 outbox。
func tunnelMutationResult(pending int, warnings []string) TunnelMutationResult {
	return TunnelMutationResult{
		DBUpdated:       true,
		FirewallPending: pending > 0,
		Warning:         firewallPendingWarning(warnings, pending),
	}
}
