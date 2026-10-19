package main

// accountEpoch 是「这份事情属于哪个登录会话」的代次快照。
//
// 客户端里同时有三种代次，判据不同、不可互相替代：
//
//	进程代次（frpc.Manager 的 gen）
//	    回答「这是这条隧道的第几个进程」。重启、重连都会推进它，
//	    换账号则不一定——退出登录停掉进程后，新账号接管同一 ID 时
//	    进程代次可能只是接着往下数。
//
//	日志代次（App.logEpoch）
//	    回答「前端见过第几段日志」。用户点一次「清空日志」就推进，
//	    与账号无关；拿它判断账号归属会把同一账号的手动清空当成换号。
//
//	账号代次（本类型）
//	    回答「这是哪个登录会话的事」。只有接入（Connect）与退出登录
//	    （Logout）推进它，因此**只有它能用来判定跨账号污染**。
//
// 这里刻意做成独立类型而不是 uint64 的别名：三类代次都是数字，混用时
// 编译器不会拦，只有等到「换了账号界面仍在刷上一段日志」才会发现——那
// 正是这个类型要防的事。
type accountEpoch uint64

// noEpoch 表示「不属于任何账号」：未接入时的启动日志、以及旧接口
// （AppendRaw）写出的行都用它。这类行按放行处理，但它们永远不来自
// 某个已结束的账号，因此不会把旧账号的内容带进来。
const noEpoch accountEpoch = 0

// known 报告这个代次是否指向某个具体账号。
func (e accountEpoch) known() bool { return e != noEpoch }

// captureEpoch 取当前账号代次。
//
// 异步任务（退出回调、后台同步、日志写入）在开始处取一次，之后每个
// 副作用前用 epochCurrent 复核：期间发生过登出/换号，凭据与账号状态
// 都已经换了一茬，旧任务的结果一律作废。
func (a *App) captureEpoch() accountEpoch {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return accountEpoch(a.authGeneration)
}

// epochCurrent 报告给定账号代次是否仍是当前代次。
//
// noEpoch 只在「当前也没有账号」时算当前：未接入时的日志属于「无账号」
// 这个状态，接入之后它就不再是当前的了——但这类行本来就产生于接入之前，
// 由序号与清空点负责，不在这里拦。
func (a *App) epochCurrent(e accountEpoch) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return uint64(e) == a.authGeneration
}

// tunnelEpoch 返回某条隧道的进程是在哪个账号代次下拉起的。
//
// ok=false 表示查不到记账：那条隧道已被删除，或退出登录已经把这张表
// 清空。两种情况都意味着**无法证明**这条隧道的输出属于当前账号，
// 调用方应当按「不处理」对待——宁可少清一次状态（下一轮同步会据实
// 对账），也不要让上一账号的行去改新账号的运行态。
func (a *App) tunnelEpoch(id uint) (accountEpoch, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	gen, ok := a.startGen[id]
	if !ok {
		return noEpoch, false
	}
	return accountEpoch(gen), true
}

// accountEpochLocked 必须在已持有 a.mu 时调用。
//
// 单独抽出来是为了让「在临界区内读账号代次」这件事显式可见：需要与
// 另一份状态同源时（例如「这个代次是否等于 current」），一定不能
// 在锁外先取一次——那是两次快照，中间的登出会让结论反过来。
func (a *App) accountEpochLocked() accountEpoch {
	return accountEpoch(a.authGeneration)
}
