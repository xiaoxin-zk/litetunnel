package main

import "time"

type retryState struct {
	attempts int
	nextAt   time.Time
}

type tunnelErr struct {
	msg string
	at  time.Time
}

func (a *App) countDisabledTunnels() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := 0
	for i := range a.tunnels {
		if a.tunnels[i].Status != tunnelStatusActive {
			n++
		}
	}
	return n
}

func (a *App) appliedConfigOf(id uint) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.applied[id]
}

func (a *App) cachedConfig(id uint, rev string) (string, bool) {
	if rev == "" {
		return "", false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.cfgRev[id] != rev {
		return "", false
	}
	text := a.applied[id]
	if text == "" {
		return "", false
	}
	return text, true
}
