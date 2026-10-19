package main

import (
	"context"
	"errors"
	"time"
)

const syncInterval = 20 * time.Second

// 连续失败时按 20s → 40s → … → 5min 退避：
// 服务端故障期间，几十条隧道每 20 秒重拉一次配置只会放大恢复时的压力。
const syncMaxBackoff = 5 * time.Minute

const configFetchConcurrency = 6

var syncRoundTimeout = 45 * time.Second

func (a *App) startAutoSync(ctx context.Context) {
	root := a.rootContext()
	go func() {
		delay := syncInterval
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-root.Done():
				return
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if err := a.autoSyncOnce(); err != nil {
				delay *= 2
				if delay > syncMaxBackoff {
					delay = syncMaxBackoff
				}
			} else {
				delay = syncInterval
			}
			timer.Reset(delay)
		}
	}()
}

func (a *App) autoSyncOnce() error {
	gen := a.currentAuthGen()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()
	if apiKey == "" {
		return nil
	}

	changed, err := a.syncLocked()
	if err != nil {
		if a.authGenCurrent(gen) {
			a.setSyncErr(err)
			a.emitState()
		}
		return err
	}

	if !a.authGenCurrent(gen) {
		return nil
	}
	if changed {
		a.emitNotice("检测到隧道变更，已自动同步并重连受影响的隧道")
	}
	a.emitState()
	return nil
}

func (a *App) syncLocked() (changed bool, err error) {
	if err := a.lockSync(a.rootContext()); err != nil {
		return false, err
	}
	defer a.unlockSync()
	return a.applySync()
}

func (a *App) nextSyncSeq() uint64 {
	return a.syncSeq.Add(1)
}

func (a *App) syncWithData(data *clientInfoData, seq uint64) (changed bool, err error) {
	ctx, cancel := a.newSyncContext()
	defer cancel()

	if err := a.lockSync(ctx); err != nil {
		return false, err
	}
	defer a.unlockSync()
	return a.syncWithDataLocked(ctx, data, seq)
}

func (a *App) syncWithDataLocked(ctx context.Context, data *clientInfoData, seq uint64) (changed bool, err error) {
	if seq <= a.appliedSyncSeq {
		return a.applySyncCtx(ctx)
	}
	return a.applySyncData(ctx, data, seq)
}

func (a *App) newSyncContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.rootContext(), syncRoundTimeout)
}

func (a *App) rootContext() context.Context {
	if a.syncRoot != nil {
		return a.syncRoot
	}
	return context.Background()
}

func (a *App) applySync() (changed bool, err error) {
	return a.applySyncCtx(a.rootContext())
}

func (a *App) applySyncCtx(parent context.Context) (changed bool, err error) {
	base := a.serverBase()

	a.mu.RLock()
	apiKey := a.cfg.APIKey
	a.mu.RUnlock()

	if base == "" || apiKey == "" {
		return false, errors.New(a.baseReason())
	}

	ctx, cancel := context.WithTimeout(parent, syncRoundTimeout)
	defer cancel()

	data, err := a.fetchClientInfo(ctx, base, apiKey)
	if err != nil {
		return false, err
	}
	return a.applySyncData(ctx, data, a.nextSyncSeq())
}
