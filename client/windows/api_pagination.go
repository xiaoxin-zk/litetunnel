package main

import (
	"context"
	"errors"
	"fmt"
)

// clientInfoPageSize 是隧道清单的分页大小。
//
// 单页控制在几十 KB：与服务端约定的上限（500）留出余量，也让一次
// 分页失败的代价尽量小。隧道总数再多，单页大小也不变。
// 用变量而不是常量：测试里要把它压小来覆盖跨页取全的路径。
var clientInfoPageSize = 200

// errTunnelListChanged 表示隧道清单在分页期间发生了变化（增删），
// 取到的条数与服务端报告的总数对不上、或出现重复。重取一轮通常就好。
var errTunnelListChanged = errors.New("隧道清单在同步期间发生变化")

// clientInfoFetchAttempts 是一致性校验失败后的整轮重取次数。
//
// 分页期间用户恰好在网页端增删隧道是可能的：与其把不完整清单交给对账
// （会把漏掉的隧道当成已删除，停进程、删配置），不如重取一轮；连续
// 两轮都对不上就报错，让下一轮自动同步再来。
const clientInfoFetchAttempts = 2

// maxClientTunnels 是客户端愿意相信的隧道总数上限。
//
// tunnel_total 直接来自服务端响应：把它当容量用之前必须先设限——负值会让
// make 直接 panic，一个被篡改/出错的极大值则会一次性分配天文数字的内存。
const maxClientTunnels = 100000

// fetchClientInfo 拉取接入信息与**完整**隧道清单。
//
// 服务端按 before_id 游标分页并返回 tunnel_total；老服务端不认这两个
// 参数、也不返回总数（0），此时等同于「一次取全部」，行为与升级前一致。
// 只按一页取会漏掉隧道：对账会把「没取到的」当成「服务端已删除」，
// 进而停掉本机进程、删掉本地配置。
func (a *App) fetchClientInfo(ctx context.Context, base, apiKey string) (*clientInfoData, error) {
	var lastErr error
	for attempt := 0; attempt < clientInfoFetchAttempts; attempt++ {
		data, err := a.fetchClientInfoOnce(ctx, base, apiKey)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !errors.Is(err, errTunnelListChanged) {
			// 网络/解析类错误重取也不会变，直接返回。
			return nil, err
		}
	}
	return nil, lastErr
}

// fetchClientInfoOnce 取一轮完整的隧道清单并做一致性校验。
func (a *App) fetchClientInfoOnce(ctx context.Context, base, apiKey string) (*clientInfoData, error) {
	var first clientInfoData
	endpoint := fmt.Sprintf("%s/api/user/client/info?limit=%d", base, clientInfoPageSize)
	if err := a.getJSON(ctx, endpoint, apiKey, &first); err != nil {
		return nil, err
	}
	if first.TunnelTotal == 0 {
		// 老服务端：没有分页也没有总数，这一页就是全部。
		if first.Tunnels == nil {
			first.Tunnels = []TunnelVO{}
		}
		return &first, nil
	}

	// 不信任服务端容量字段：负值、或大到不像真实账号的总数，直接按清单
	// 异常处理，绝不拿它去 make（负值 panic、极大值 OOM）。
	if first.TunnelTotal < 0 || first.TunnelTotal > maxClientTunnels {
		return nil, fmt.Errorf("%w：服务端报告的隧道总数异常（%d）",
			errTunnelListChanged, first.TunnelTotal)
	}

	// 预分配只取一个温和的上限：总数再大也是靠 append 动态增长，
	// 容量给太多毫无意义，还可能因一个错误总数吃掉大量内存。
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
		// 服务端先查总数、再单独查列表，两次查询之间隧道可能被删空：
		// 响应就成了「总数 > 0、列表为空」。这里绝不能进入游标计算
		// （对空切片取末元素会 panic，自动同步协程里的 panic 会直接
		// 终止客户端），按「清单已变化」重取。
		return nil, fmt.Errorf("%w：服务端报告 %d 条但本页为空",
			errTunnelListChanged, first.TunnelTotal)
	}

	for int64(len(all)) < first.TunnelTotal {
		// 游标 = 已取到的最小 id，下一页取比它更小的（服务端按 id 倒序）。
		cursor := all[len(all)-1].ID
		var page clientInfoData
		endpoint := fmt.Sprintf("%s/api/user/client/info?before_id=%d&limit=%d",
			base, cursor, clientInfoPageSize)
		if err := a.getJSON(ctx, endpoint, apiKey, &page); err != nil {
			// 取到一半失败也必须报错：拿着不完整的清单去对账，
			// 会把后面几页的隧道当成已删除。
			return nil, fmt.Errorf("拉取隧道清单第 %d 页失败: %w", len(all)/clientInfoPageSize+1, err)
		}
		// 版本校验：分页期间删一条、又新增一条 id 更大的，总数不变，
		// 新隧道却落在游标之前永远取不到——只比条数发现不了。
		// 老服务端没有版本字段（空串），跳过这项校验。
		if first.ListVersion != "" && page.ListVersion != first.ListVersion {
			return nil, fmt.Errorf("%w：列表版本由 %s 变为 %s",
				errTunnelListChanged, first.ListVersion, page.ListVersion)
		}
		if len(page.Tunnels) == 0 {
			// 服务端说还有、这一页却是空的：不能静默当成取全了，
			// 交给下面的一致性校验去重取/报错。
			break
		}
		if err := appendPage(page.Tunnels); err != nil {
			return nil, err
		}
	}

	// 一致性校验：分页期间有增删时条数会对不上（漏项），
	// 不完整的清单绝不能进入对账。
	if int64(len(all)) != first.TunnelTotal {
		return nil, fmt.Errorf("%w：取到 %d 条，服务端报告 %d 条",
			errTunnelListChanged, len(all), first.TunnelTotal)
	}

	first.Tunnels = all
	return &first, nil
}
