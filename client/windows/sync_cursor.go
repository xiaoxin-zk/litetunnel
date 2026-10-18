package main

// 本文件是同步对账的「进度协调器」：一轮同步里哪条隧道已经落定、哪条因为
// 截止时间根本没轮到，以及下一轮该从哪里开始。
//
// 四件事的分工（都在 client/windows 下，读代码时按这个顺序看）：
//
//	配置获取  sync_fetch.go              —— 并发拉取，结果按完成顺序流出
//	应用结果  sync_apply.go              —— 逐条落盘/起停，得出「落定」与否
//	截止时间  sync_process.go            —— 三道闸与单条隧道的启动
//	          sync_schedule.go           —— 整轮预算与后台周期
//	游标推进  本文件                       —— 只按落定推进，未落定的下一轮优先
//
// 为什么单独抽出来：游标推进原先只是 applySyncData 末尾的几行，靠
// streamTunnelConfigs 的「派发计数」推算。**派发不等于应用**——截止时间一到，
// 已经派发出去的隧道会在 applyCfg 开头直接 return（不落盘、不启动、不记失败），
// 可它们已经被计入派发数，游标于是越过它们。被越过的隧道要等整整一圈才会再
// 被看到；隧道多、轮次又被截止时间砍短时，这一圈就是好几分钟，用户侧表现为
// 「刚加的隧道一直离线，重启客户端也没用」（重启只是把游标归零，过一会儿
// 又回到同一个位置）。

// syncRound 是一轮对账的进度账。
//
// 它只记录「这一轮发生了什么」，不持有 App 的任何状态：游标的最终落点由
// nextStart 算出来，写回 App.syncStart 仍由 applySyncData 负责——那里持有
// syncMu，是唯一该改游标的地方。
type syncRound struct {
	// order 是本轮的处理顺序，元素是隧道 ID（已按 syncStart 环形左移）。
	order []uint
	// settled 记录已落定的隧道。
	//
	// 「落定」= 走到了明确结论，只有两种：
	//   - 成功应用：配置落盘并启动、重启成功，或本来就不需要动；
	//   - 明确失败：失败已经记进隧道行与退避（failSync / failStart），
	//     下一轮按退避时间再来，不需要「优先」插队。
	//
	// 唯一不落定的是「截止时间已过、这一轮没轮到它」：它什么都没做错，
	// 只是没排上，下一轮必须重新轮到，所以绝不能算成已处理。
	settled map[uint]bool
	// dispatchPos 是本轮会派发配置请求的隧道在 order 里的下标，按派发顺序
	// 排列；dispatched 是实际派发出去的条数（截止时间可能让派发提前结束）。
	//
	// 这两个字段只服务于一种兜底情况：整轮一条都没落定（见 nextStart）。
	dispatchPos []int
	dispatched  int
}

// newSyncRound 为一轮对账建账。order 必须已经按 syncStart 环形左移过，
// dispatchPos 是这批隧道里「需要发配置请求」的那些在 order 中的下标。
func newSyncRound(order []TunnelVO, dispatchPos []int) *syncRound {
	ids := make([]uint, len(order))
	for i := range order {
		ids[i] = order[i].ID
	}
	return &syncRound{
		order:       ids,
		settled:     make(map[uint]bool, len(order)),
		dispatchPos: dispatchPos,
	}
}

// settle 记下一条隧道已经落定。
func (r *syncRound) settle(id uint) {
	r.settled[id] = true
}

// setDispatched 记下本轮实际派发出去的配置请求数。
//
// 必须在结果通道关闭之后调用：派发在独立协程里进行，提前读会读到中间值。
func (r *syncRound) setDispatched(n int) {
	r.dispatched = n
}

// settledPrefix 返回从本轮起点开始、连续落定的隧道条数。
//
// 之所以是「连续前缀」而不是「落定总数」：环形顺序下，一旦某一条没落定，
// 它后面的位置就都还没轮到——把游标推过它，等于把它跳过（这正是缺陷 2）。
func (r *syncRound) settledPrefix() int {
	n := len(r.order)
	i := 0
	for i < n && r.settled[r.order[i]] {
		i++
	}
	return i
}

// nextStart 算出下一轮应当从清单的哪个位置开始。
//
// rot 是本轮环形左移的偏移量，n 是本轮待处理隧道数；返回值与 App.syncStart
// 的含义一致：**未旋转清单**里的下标。
//
// 三种情况：
//
//  1. 整轮全部落定：回到本轮起点。清单没变时顺序与「派发完一整轮」完全一致，
//     与旧实现的行为相同。
//
//  2. 落定了一段、后面没轮到：停在**第一个未落定的位置**。
//
//     环形顺序下，「从第一个未落定处开始」恰好等价于「把未落定集合整体排到
//     最前」——未落定的下标一定是某个位置到末尾的连续后缀（落定与否是按
//     位置从前往后判定的），把它们前置、与从后缀开头开始遍历，得到的是
//     同一个顺序。所以不需要额外维护一张按隧道 ID 的优先表：那张表还要在
//     清单增删时保持同步，一旦对不上就是新的跳过来源。
//
//  3. 一条都没落定：本轮颗粒无收。这时停在原地只会让同样的前几条反复吃掉
//     整笔预算，尾部永远轮不到——正是旧实现用「派发进度」轮转要解决的
//     「尾部饿死」（见 syncStart 的注释）。所以退回按派发进度轮转：这一轮
//     反正什么都没应用，谈不上「跳过」，而轮转让下一条隧道有机会被处理。
//
//     这种情况在真实环境里意味着整轮网络都不通（所有请求都撞上截止时间），
//     此时轮转是唯一还能推进的事情。
func (r *syncRound) nextStart(rot, n int) int {
	if n <= 0 {
		return rot
	}
	prefix := r.settledPrefix()
	switch {
	case prefix == n:
		return rot % n
	case prefix > 0:
		return (rot + prefix) % n
	}

	// 兜底：按派发进度轮转。派发是从本轮起点开始、按顺序进行的，派发到哪儿
	// 就意味着这一轮走到哪儿。
	if d := r.dispatched; d > 0 {
		if d > len(r.dispatchPos) {
			d = len(r.dispatchPos)
		}
		if d > 0 {
			// dispatchPos 是**环形左移之后**的下标，而 syncStart 是原清单里的
			// 位置，所以要加回 rot——漏掉这一步游标会往回走。
			return (rot + r.dispatchPos[d-1] + 1) % n
		}
	}
	return rot % n
}
