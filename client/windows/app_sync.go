package main

import "context"

func (a *App) syncGateChan() chan struct{} {
	a.gateOnce.Do(func() {
		if a.syncGate == nil {
			a.syncGate = make(chan struct{}, 1)
		}
	})
	return a.syncGate
}

func (a *App) lockSync(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case a.syncGateChan() <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) lockSyncBlocking() {
	a.syncGateChan() <- struct{}{}
}

func (a *App) unlockSync() {
	<-a.syncGateChan()
}
