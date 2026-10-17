package service

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
