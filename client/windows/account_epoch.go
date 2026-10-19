package main

type accountEpoch uint64

const noEpoch accountEpoch = 0

func (e accountEpoch) known() bool { return e != noEpoch }

func (a *App) captureEpoch() accountEpoch {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return accountEpoch(a.authGeneration)
}

func (a *App) epochCurrent(e accountEpoch) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return uint64(e) == a.authGeneration
}

func (a *App) tunnelEpoch(id uint) (accountEpoch, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	gen, ok := a.startGen[id]
	if !ok {
		return noEpoch, false
	}
	return accountEpoch(gen), true
}

func (a *App) accountStillLocked(acct accountEpoch) bool {
	if !acct.known() {
		return true
	}
	return uint64(acct) == a.authGeneration
}

func (a *App) accountEpochLocked() accountEpoch {
	return accountEpoch(a.authGeneration)
}
