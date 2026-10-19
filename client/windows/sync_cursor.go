package main

type syncRound struct {
	order       []uint
	settled     map[uint]bool
	dispatchPos []int
	dispatched  int
}

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

func (r *syncRound) settle(id uint) {
	r.settled[id] = true
}

func (r *syncRound) setDispatched(n int) {
	r.dispatched = n
}

func (r *syncRound) settledPrefix() int {
	n := len(r.order)
	i := 0
	for i < n && r.settled[r.order[i]] {
		i++
	}
	return i
}

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

	if d := r.dispatched; d > 0 {
		if d > len(r.dispatchPos) {
			d = len(r.dispatchPos)
		}
		if d > 0 {
			return (rot + r.dispatchPos[d-1] + 1) % n
		}
	}
	return rot % n
}
