package service

import (
	"context"
	"log"
	"time"
)

const (
	proxySnapshotTTL      = 2 * time.Second
	proxySnapshotMaxLists = 4
)

type proxyDrainTarget struct {
	Name        string `json:"name"`
	ClientID    string `json:"client_id,omitempty"`
	LastStartAt int64  `json:"last_start_at,omitempty"`
}

func (t proxyDrainTarget) identifiable() bool {
	return t.ClientID != "" || t.LastStartAt > 0
}

func (t proxyDrainTarget) matches(cur FrpsProxy) bool {
	if t.ClientID != "" && cur.ClientID != t.ClientID {
		return false
	}
	if t.LastStartAt > 0 && cur.Status.LastStartAt != t.LastStartAt {
		return false
	}
	return true
}

func targetOf(p FrpsProxy) proxyDrainTarget {
	return proxyDrainTarget{
		Name:        p.Name,
		ClientID:    p.ClientID,
		LastStartAt: p.Status.LastStartAt,
	}
}

type proxySnapshot struct {
	byName  map[string]FrpsProxy
	fetched time.Time
}

func (s *proxySnapshot) lookup(name string) (FrpsProxy, bool) {
	p, ok := s.byName[name]
	return p, ok
}

func (s *proxySnapshot) discoveryTargets(userID uint, prefix string, notAfter time.Time) []proxyDrainTarget {
	out := make([]proxyDrainTarget, 0, len(s.byName))
	for _, p := range s.byName {
		if !topLevelPrefix(p.Name, prefix) {
			continue
		}
		if p.Status.LastStartAt > 0 && !notAfter.IsZero() {
			if startedAt := time.Unix(p.Status.LastStartAt, 0); !startedAt.Before(notAfter.Add(-time.Second)) {
				log.Printf("[user] 用户 %d 的代理 %q 在禁用之后才启动（%s），跳过关闭",
					userID, p.Name, startedAt.Format(time.RFC3339))
				continue
			}
		}
		out = append(out, targetOf(p))
	}
	return out
}

type proxySnapshotCache struct {
	svc     *Services
	snap    *proxySnapshot
	lists   int
	listErr error
}

func newProxySnapshotCache(svc *Services) *proxySnapshotCache {
	return &proxySnapshotCache{svc: svc}
}

func (c *proxySnapshotCache) current(ctx context.Context) (*proxySnapshot, error) {
	if c.snap != nil && time.Since(c.snap.fetched) < proxySnapshotTTL {
		return c.snap, nil
	}
	if c.snap != nil && c.lists >= proxySnapshotMaxLists {
		return c.snap, nil
	}
	list, err := c.svc.Frps.ListProxies(ctx)
	if err != nil {
		c.listErr = err
		if c.snap != nil {
			log.Printf("[proxy-drain] 刷新代理列表失败，沿用上次快照继续（身份判定仍受用户锁与 lastStartAt 保护）: %v", err)
			return c.snap, nil
		}
		return nil, err
	}
	c.lists++
	c.listErr = nil
	c.snap = newProxySnapshot(list)
	return c.snap, nil
}

func (c *proxySnapshotCache) lookup(ctx context.Context, name string) (FrpsProxy, bool, error) {
	snap, err := c.current(ctx)
	if err != nil {
		return FrpsProxy{}, false, err
	}
	if p, ok := snap.lookup(name); ok {
		return p, true, nil
	}
	if c.lists < proxySnapshotMaxLists {
		prev := c.snap
		c.snap = nil
		snap, err = c.current(ctx)
		if err != nil {
			c.snap = prev
			return FrpsProxy{}, false, err
		}
		if p, ok := snap.lookup(name); ok {
			return p, true, nil
		}
	}
	return FrpsProxy{}, false, nil
}

func newProxySnapshot(list []FrpsProxy) *proxySnapshot {
	byName := make(map[string]FrpsProxy, len(list))
	for _, p := range list {
		byName[p.Name] = p
	}
	return &proxySnapshot{byName: byName, fetched: time.Now()}
}
