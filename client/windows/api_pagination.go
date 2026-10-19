package main

import (
	"context"
	"errors"
	"fmt"
)

var clientInfoPageSize = 200

var errTunnelListChanged = errors.New("隧道清单在同步期间发生变化")

const clientInfoFetchAttempts = 2

const maxClientTunnels = 100000

func (a *App) fetchClientInfo(ctx context.Context, base, apiKey string) (*clientInfoData, error) {
	var lastErr error
	for attempt := 0; attempt < clientInfoFetchAttempts; attempt++ {
		data, err := a.fetchClientInfoOnce(ctx, base, apiKey)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !errors.Is(err, errTunnelListChanged) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (a *App) fetchClientInfoOnce(ctx context.Context, base, apiKey string) (*clientInfoData, error) {
	var first clientInfoData
	endpoint := fmt.Sprintf("%s/api/user/client/info?limit=%d", base, clientInfoPageSize)
	if err := a.getJSON(ctx, endpoint, apiKey, &first); err != nil {
		return nil, err
	}
	if first.TunnelTotal == 0 {
		if first.Tunnels == nil {
			first.Tunnels = []TunnelVO{}
		}
		return &first, nil
	}

	if first.TunnelTotal < 0 || first.TunnelTotal > maxClientTunnels {
		return nil, fmt.Errorf("%w：服务端报告的隧道总数异常（%d）",
			errTunnelListChanged, first.TunnelTotal)
	}

	prealloc := first.TunnelTotal
	if prealloc > 4096 {
		prealloc = 4096
	}
	all := make([]TunnelVO, 0, prealloc)
	seen := make(map[uint]bool, prealloc)
	appendPage := func(page []TunnelVO) error {
		for _, tun := range page {
			if seen[tun.ID] {
				return fmt.Errorf("%w：隧道 %d 重复出现", errTunnelListChanged, tun.ID)
			}
			seen[tun.ID] = true
			all = append(all, tun)
		}
		return nil
	}
	if err := appendPage(first.Tunnels); err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("%w：服务端报告 %d 条但本页为空",
			errTunnelListChanged, first.TunnelTotal)
	}

	for int64(len(all)) < first.TunnelTotal {
		cursor := all[len(all)-1].ID
		var page clientInfoData
		endpoint := fmt.Sprintf("%s/api/user/client/info?before_id=%d&limit=%d",
			base, cursor, clientInfoPageSize)
		if err := a.getJSON(ctx, endpoint, apiKey, &page); err != nil {
			return nil, fmt.Errorf("拉取隧道清单第 %d 页失败: %w", len(all)/clientInfoPageSize+1, err)
		}
		if first.ListVersion != "" && page.ListVersion != first.ListVersion {
			return nil, fmt.Errorf("%w：列表版本由 %s 变为 %s",
				errTunnelListChanged, first.ListVersion, page.ListVersion)
		}
		if len(page.Tunnels) == 0 {
			break
		}
		if err := appendPage(page.Tunnels); err != nil {
			return nil, err
		}
	}

	if int64(len(all)) != first.TunnelTotal {
		return nil, fmt.Errorf("%w：取到 %d 条，服务端报告 %d 条",
			errTunnelListChanged, len(all), first.TunnelTotal)
	}

	first.Tunnels = all
	return &first, nil
}
