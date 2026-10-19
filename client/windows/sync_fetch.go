package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

func (a *App) fetchTunnelConfig(ctx context.Context, base, apiKey string, id uint) (string, string, error) {
	endpoint := fmt.Sprintf("%s/api/user/client/config?tunnel_id=%d", base, id)
	text, rev, err := a.getRawWithRev(ctx, endpoint, apiKey)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(text), rev, nil
}

type cfgResult struct {
	tunnel TunnelVO
	text   string
	rev    string
	err    error
}

func (a *App) streamTunnelConfigs(ctx context.Context, base, apiKey string, tunnels []TunnelVO) (<-chan cfgResult, *atomic.Int64) {
	dispatched := &atomic.Int64{}
	results := make(chan cfgResult, len(tunnels))
	if len(tunnels) == 0 {
		close(results)
		return results, dispatched
	}

	workers := configFetchConcurrency
	if workers > len(tunnels) {
		workers = len(tunnels)
	}

	jobs := make(chan TunnelVO)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-jobs:
					if !ok {
						return
					}
					text, rev, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
					select {
					case results <- cfgResult{tunnel: t, text: text, rev: rev, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range tunnels {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
				dispatched.Add(1)
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	return results, dispatched
}
