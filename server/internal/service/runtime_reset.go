package service

const resetGenUnknown int64 = -1

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

func (r *Runtime) resetSkipValid(userID uint, gen uint64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return gen > r.resetVoidUntil[userID]
}

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

func (r *Runtime) UnmarkTrafficResetPending(userID uint, gen uint64) {
	r.resetMu.Lock()
	defer r.resetMu.Unlock()
	r.unmarkTrafficResetPendingLocked(userID, gen)
}

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

func (r *Runtime) lockTrafficReset() func() {
	r.resetMu.Lock()
	return r.resetMu.Unlock
}
