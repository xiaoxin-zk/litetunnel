package service

// 本文件是代理断流的「身份校验」阶段：决定一条代理是不是**要关的那一个实例**。
//
// # 为什么需要单独一层
//
// frps 上的代理名由「frp user + 隧道名」组成，而这两段都不含实例信息。
// 客户端重连（禁用被撤销、网络抖动、进程重启）会用**完全相同**的名字重新
// 注册，frps 立刻把新的连接挂上去。此时按名字调 CloseProxy，关掉的是新实例：
// 用户那边的表现是「刚连上又断」，而日志里只有一行「已关闭代理 xxx」，
// 看不出这是误杀。所以关闭前必须比对实例身份。
//
// # 一次批量列表 + 窗口复用
//
// 原先每条代理关闭前都重新拉一次全量列表做复查：N 条代理就是 N 次分页抓取，
// frps 稍慢就会把 15 秒预算耗尽，只关掉一部分。这里改成「一次批量列表建立
// name → 实例身份快照」，同轮内的复查都读这份快照；只有快照超过窗口（说明
// 世界可能已经变了）才重拉一次。取舍的理由：
//
//   - 快照窗口内的误判概率与「原来每条都重拉」相比只是从 0 变成很小，
//     而请求数从 O(N) 降到 O(1)（正常情况下整轮只有 1 次）；
//   - 真正兜住「关闭瞬间被重新注册」的是**用户锁 + lastStartAt 水位**
//     （见 proxy_drain.go 的 closeDrainedProxy），快照只负责把「明显不是同一个
//     实例」的候选提前剔掉；
//   - 身份判不出来时一律跳过：漏关只是多跑一会儿流量，误杀是可见故障。

import (
	"context"
	"log"
	"time"
)

const (
	// proxySnapshotTTL 是身份快照的有效期。
	//
	// 太短等于回到「每条代理重拉一次」，太长则关闭决策依据的世界可能已经
	// 变了好几轮。取 2 秒：正常一轮断流（含每条取锁、发 DELETE）大概就在
	// 这个量级内完成，此时整轮只拉一次列表；frps 明显变慢时每 2 秒重拉一次，
	// 相比「每条一次」仍是数量级的下降。
	proxySnapshotTTL = 2 * time.Second
	// proxySnapshotMaxLists 是单轮断流里最多重拉几次列表。
	//
	// 必须有上限：关闭持续失败（frps 半死、DELETE 一直超时）时，每处理一条
	// 都会因为快照过期而重拉，把时间预算全花在拉列表上。到上限后不再重拉，
	// 直接把剩余候选记为「残留、待下一轮」——宁可让后台重试器多跑一轮，
	// 也不要占着禁用/删除请求的时间预算空转。
	proxySnapshotMaxLists = 4
)

// proxyDrainTarget 是一条待关闭代理的实例身份快照。
//
// 字段与 frps 返回的 FrpsProxy 一一对应，但**刻意不复用 FrpsProxy 本身**：
// 这是一份「发现时刻」的历史快照，语义上是「要关的是这个东西」，而不是
// 「frps 现在是这样」。混用同一个类型会让调用方误以为它是最新状态。
type proxyDrainTarget struct {
	Name string `json:"name"`
	// ClientID 是 frpc 实例标识（frps 分配）；老版本可能为空。
	ClientID string `json:"client_id,omitempty"`
	// LastStartAt 是代理本次启动时刻（Unix 秒）；老版本可能为 0。
	LastStartAt int64 `json:"last_start_at,omitempty"`
}

// identifiable 判断这条代理有没有可用于身份比对的字段。
//
// 两个字段**都**缺失时身份不可判定，此时绝不能按名字关：客户端重连会用同一个
// 名字重新注册，按名字关等于随机踢人。只有其中之一时仍可比较（老版本 frps
// 不返回 lastStartAt，不能因此就完全断不了流）。
func (t proxyDrainTarget) identifiable() bool {
	return t.ClientID != "" || t.LastStartAt > 0
}

// matches 判断 cur 是否仍是发现时看到的那个代理实例。
//
// 只比较**快照里存在**的字段：空字段代表「当时 frps 没告诉我们」，不是
// 「当时是空值」，拿它去比会把所有记录都判成不匹配。
func (t proxyDrainTarget) matches(cur FrpsProxy) bool {
	if t.ClientID != "" && cur.ClientID != t.ClientID {
		return false
	}
	if t.LastStartAt > 0 && cur.Status.LastStartAt != t.LastStartAt {
		return false
	}
	return true
}

// targetOf 把 frps 的一条代理记录转成身份快照。
func targetOf(p FrpsProxy) proxyDrainTarget {
	return proxyDrainTarget{
		Name:        p.Name,
		ClientID:    p.ClientID,
		LastStartAt: p.Status.LastStartAt,
	}
}

// proxySnapshot 是一次批量列表的结果，附带「何时取的」。
type proxySnapshot struct {
	byName  map[string]FrpsProxy
	fetched time.Time
}

// lookup 从快照里取某条代理的当前记录。
func (s *proxySnapshot) lookup(name string) (FrpsProxy, bool) {
	p, ok := s.byName[name]
	return p, ok
}

// discoveryTargets 按前缀与时间水位筛出本轮的候选代理。
//
// 两条过滤缺一不可：
//
//   - 前缀：只碰该用户的代理。前缀来自 FrpUserOf（"lt_u<ID>."），写错了就会
//     关到别人的代理——这是最外层、也最危险的判据；
//   - lastStartAt 水位：代理在禁用生效之后才启动 = 重新启用后的新连接（或被
//     客户端重连重新注册过），关掉它就等于把刚放行的人又踢下线。缺失
//     （老版本 frps）时不作判断，退回只靠代次与锁。
func (s *proxySnapshot) discoveryTargets(userID uint, prefix string, notAfter time.Time) []proxyDrainTarget {
	out := make([]proxyDrainTarget, 0, len(s.byName))
	for _, p := range s.byName {
		if !topLevelPrefix(p.Name, prefix) {
			continue
		}
		if p.Status.LastStartAt > 0 && !notAfter.IsZero() {
			if startedAt := time.Unix(p.Status.LastStartAt, 0); startedAt.After(notAfter) {
				log.Printf("[user] 用户 %d 的代理 %q 在禁用之后才启动（%s），跳过关闭",
					userID, p.Name, startedAt.Format(time.RFC3339))
				continue
			}
		}
		out = append(out, targetOf(p))
	}
	return out
}

// proxySnapshotCache 在一轮断流内复用批量列表结果。
//
// 刻意不是全局缓存：它绑定「这一次断流」的生命周期，用完即弃。做成全局的话，
// 一次 frps 抖动留下的旧快照会被下一个用户的断流读到，拿它判断身份等于用
// 几秒前（甚至更久）的世界做不可逆的关闭动作。
type proxySnapshotCache struct {
	svc   *Services
	snap  *proxySnapshot
	lists int
	// listErr 记录最近一次重拉的错误：重拉失败时**沿用旧快照**，因为旧快照
	// 仍然比「没有快照」强——它至少是真实存在过的 frps 状态。
	listErr error
}

// newProxySnapshotCache 建一个空缓存；首次 current 时才真正请求。
func newProxySnapshotCache(svc *Services) *proxySnapshotCache {
	return &proxySnapshotCache{svc: svc}
}

// current 返回当前可用的快照，必要时拉取。
//
// 拉取失败必须**返回错误**而不是空快照：空快照会让调用方以为「代理都没了」，
// 于是把整轮当成「没有残留」收尾、连待办都不留——这正是缺陷 1 里
// 「frps 不可用就当没事发生」的同一种错误。
func (c *proxySnapshotCache) current(ctx context.Context) (*proxySnapshot, error) {
	if c.snap != nil && time.Since(c.snap.fetched) < proxySnapshotTTL {
		return c.snap, nil
	}
	if c.snap != nil && c.lists >= proxySnapshotMaxLists {
		// 已到重拉上限：沿用旧快照。它的世界可能已经变了，但这里的目标是
		// 不把时间预算耗在拉列表上；身份判定还有用户锁与 lastStartAt 兜底，
		// 判不出来时 closeDrainedProxy 会跳过并记为残留。
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

// lookup 在快照里查一条代理的当前记录。
//
// 第二个返回值 false 表示「快照里已经没有这条代理」——它可能真的退出了，
// 也可能只是快照过旧。为了不让后一种情况变成「明明还在跑却判定为空」，
// 这里在窗口外会先尝试刷新一次再查：刷新失败就退回旧快照的判断（旧快照里
// 没有 = 至少在上次列表时它已经不在）。
func (c *proxySnapshotCache) lookup(ctx context.Context, name string) (FrpsProxy, bool, error) {
	snap, err := c.current(ctx)
	if err != nil {
		return FrpsProxy{}, false, err
	}
	if p, ok := snap.lookup(name); ok {
		return p, true, nil
	}
	// 快照里没有：可能是刚退出，也可能是快照过旧。强制刷新一次再确认；
	// 刷新失败不改变结论（旧快照里确实没有它），但要如实返回错误，
	// 让调用方按「残留」处理而不是静默当成已消失。
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

// newProxySnapshot 把列表结果转成按名字索引的快照。
//
// 同名项只保留最后一条：ListProxies 已经会拒绝重复项（重复会让同一段流量
// 被计两次），所以这里重复意味着数据不可信；保留最后一条是保守选择——
// 它对应的仍是同一个代理名，关闭动作的可逆性由身份比对保证。
func newProxySnapshot(list []FrpsProxy) *proxySnapshot {
	byName := make(map[string]FrpsProxy, len(list))
	for _, p := range list {
		byName[p.Name] = p
	}
	return &proxySnapshot{byName: byName, fetched: time.Now()}
}
