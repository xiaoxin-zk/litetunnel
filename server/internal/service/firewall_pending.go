package service

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// pendingFW 是一条待重试的防火墙端口操作。
//
// 按**端口**保存而不是按隧道：一个端口同时只可能有一个意图，
// 后来的意图覆盖先前的。这一点很重要——「停用某隧道（要收回端口）」失败
// 之后用户又把它启用了（要放行），若两条记录并存，后台重试会照着旧的
// 那条把端口关掉，正好关掉刚启用的隧道。
type pendingFW struct {
	open      bool
	proto     string
	attempts  int
	lastErr   string
	exhausted bool
	// gen 是这条意图的版本号，来自 Services.fwGen；落库用它做条件写。
	gen int64
}

const (
	// firewallRetryInterval 是重试待处理端口操作的间隔。
	firewallRetryInterval = 2 * time.Minute
	// pendingFWMaxAttempts 是同一端口的最大重试次数。
	//
	// 必须有上限：有些失败是**永久性**的（端口在保护列表里、不在端口池内），
	// 无限重试只会每两分钟刷一次同样的日志。到上限后终止自动处理——
	// 记录保留下来（exhausted=true），由管理页暴露给管理员，而不是
	// 像以前那样删掉记录、只留一行迟早被滚动掉的日志。
	pendingFWMaxAttempts = 5
	// pendingFWLimit 是待重试队列的长度上限，防止异常情况下无限增长。
	pendingFWLimit = 512
)

// markFirewallPending 记下一条待重试的端口操作（内存 + 落库）。
//
// 返回 false 表示**没有**入队（队列已满且这是一个新端口）：这条意图既没执行、
// 也没进入重试队列，属于永久丢失，调用方必须据此明确报错，否则会出现
// 「隧道已启用、端口未放行、管理页也没有待办」的永久不一致。
func (s *Services) markFirewallPending(port int, proto string, open bool) bool {
	s.fwMu.Lock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	prev, exists := s.fwPending[port]
	// 已有记录时**覆盖**为最新意图（而不是保留旧的）：见 pendingFW 的注释。
	// 覆盖时保留已累计的重试次数，避免「意图反复变化」把上限重置掉。
	//
	// 例外：旧意图已经重试耗尽、而这回是**另一个**意图时，从零开始计——
	// 意图已经变了，说明端口的世界变了（新隧道启用、旧的已删），
	// 新意图该有自己完整的一轮预算；沿用旧计数会让它第一次失败就再次
	// 被判为终态。同一意图的再次尝试不在此列，那正是上限要拦的。
	attempts := 0
	if exists {
		attempts = prev.attempts
		if prev.exhausted && (prev.open != open || prev.proto != proto) {
			attempts = 0
		}
	} else if len(s.fwPending) >= pendingFWLimit {
		s.fwMu.Unlock()
		log.Printf("[firewall] 待处理端口操作已达上限 %d，端口 %d 不再进入重试队列，需要人工清理",
			pendingFWLimit, port)
		return false
	}
	s.fwGen++
	item := pendingFW{open: open, proto: proto, attempts: attempts, gen: s.fwGen}
	s.fwPending[port] = item
	s.fwMu.Unlock()

	// 落库放在锁外：这是 IO，不该让建/删隧道的请求排在它后面。
	s.persistPending(port, item)
	return true
}

// persistPending 把一条待办写入数据库（写失败只记日志：内存里那份仍然有效，
// 只是这次重启后会丢——比让整个防火墙操作失败要好）。
func (s *Services) persistPending(port int, item pendingFW) {
	rec := model.FirewallPending{
		Port:       port,
		Proto:      item.proto,
		Open:       item.open,
		Attempts:   item.attempts,
		Exhausted:  item.exhausted,
		Generation: item.gen,
		LastErr:    truncate(item.lastErr, 255),
	}
	// 条件 upsert：只允许「版本号 ≥ 库里那代」的写回覆盖旧记录。
	// 落库在锁外，旧意图的写回可能晚于新意图——无条件覆盖会让旧「收回」
	// 顶掉新「放行」。等号允许「同一代的重试次数/终态更新」正常落库。
	if err := s.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"proto", "open", "attempts", "exhausted", "generation", "last_err",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr("excluded.generation >= lt_firewall_pending.generation"),
		}},
	}).Create(&rec).Error; err != nil {
		log.Printf("[firewall] 待办落库失败（端口 %d，重启后会丢失这条意图）: %v", port, err)
	}
}

// dropPending 从内存与数据库里同时移除一条待办，但只在它仍是**同代**时。
//
// 旧任务的删除可能晚于新意图的登记：无条件按端口删会把新待办一起删掉，
// 重启后那条新意图就没了。版本号让删除只作用于「我要删的那代」。
func (s *Services) dropPending(port int, gen int64) {
	s.fwMu.Lock()
	if cur, ok := s.fwPending[port]; ok && cur.gen == gen {
		delete(s.fwPending, port)
	}
	s.fwMu.Unlock()

	if err := s.DB.Where("port = ? AND generation = ?", port, gen).
		Delete(&model.FirewallPending{}).Error; err != nil {
		log.Printf("[firewall] 清除待办记录失败（端口 %d）: %v", port, err)
	}
}

// loadPendingFirewall 把落库的待办读回内存。启动时调用一次。
//
// 读回来的意图仍然要经过 portIntentValid 校验才会执行——重启期间端口可能
// 已经被新隧道复用，照着旧意图关掉它就是把新隧道的规则关掉了。
func (s *Services) loadPendingFirewall() {
	var recs []model.FirewallPending
	if err := s.DB.Find(&recs).Error; err != nil {
		log.Printf("[firewall] 读取待办记录失败（本轮不恢复重试队列）: %v", err)
		return
	}
	if len(recs) == 0 {
		return
	}

	s.fwMu.Lock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	for _, r := range recs {
		s.fwPending[r.Port] = pendingFW{
			open: r.Open, proto: r.Proto, attempts: r.Attempts, lastErr: r.LastErr,
			exhausted: r.Exhausted, gen: r.Generation,
		}
		if r.Generation > s.fwGen {
			// 新登记的意图必须比库里所有旧代都大，否则条件写永远不生效。
			s.fwGen = r.Generation
		}
	}
	n := len(s.fwPending)
	s.fwMu.Unlock()
	log.Printf("[firewall] 从数据库恢复了 %d 条待处理的端口操作，将继续重试", n)
}

// applyPortIntent 执行一次端口操作；失败时记入待重试队列。
//
// 失败不能只写日志：数据库状态已经改了、接口也返回了成功，而规则没变。
// 启动时的规则对齐只补开不收回，放行失败更是没有任何地方会再尝试，
// 所以两种失败都必须排队重试。
//
// 返回值 acted 表示这次确实动了手，err 是动手时的错误（acted 为 false 时
// err 恒为 nil）——对账需要区分「放行成功」「放行失败」「按现状不该放行」。
func (s *Services) applyPortIntent(port int, proto string, open bool) (acted bool, err error) {
	if port <= 0 {
		return false, nil
	}
	// 与「重试该端口」互斥：否则可能刚放行就被一条过时的重试任务关掉。
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()
	return s.applyPortIntentLocked(port, proto, open)
}

// applyPortIntentLocked 在**已持有该端口锁**的前提下执行端口操作。
//
// 单独拆出来是给「事务提交前就已取锁」的调用方用（建隧道那条路径）：
// 在那里再调一次 applyPortIntent 会重复加锁，直接死锁。
//
// # 动手之前先按数据库现状校验意图
//
// 立即路径（启停隧道、删除隧道）同样是「先改数据库、再动防火墙」，
// 两步之间可能插进别的请求：
//
//   - 两个相反的状态切换并发时，较早那个可能最后才执行防火墙操作，
//     把规则改成与最终数据库状态相反的样子（用户看到「已启用但连不上」）；
//   - 删除隧道后端口立刻被新隧道复用，那条删除的收回会把新隧道的规则关掉。
//
// 校验放在端口锁内，于是「读状态 + 动手」是原子的：最后执行的那次一定
// 与数据库的最终状态一致，不一致的那次会主动跳过。
//
// 注意这里**不需要**把数据库变更也包进锁里：每个请求都在自己的数据库
// 变更之后才动手，而校验读的就是当下最新的状态。多端口批量删除时逐端口
// 取锁、不同时持有，也就不存在锁序问题。
func (s *Services) applyPortIntentLocked(port int, proto string, open bool) (acted bool, err error) {
	if port <= 0 {
		return false, nil
	}

	valid, verr := s.portIntentValid(port, open)
	if verr != nil {
		// 读不出状态：不动手，但记住意图等下一轮。
		if !s.markFirewallPending(port, proto, open) {
			return false, ErrFirewallQueueFull
		}
		log.Printf("[firewall] 无法确认端口 %d 的当前状态，本次不动手、已加入重试队列: %v", port, verr)
		return false, nil
	}
	if !valid {
		log.Printf("[firewall] 端口 %d 的意图已过时（当前状态与%s不符），本次跳过", port, actionName(open))
		return false, nil
	}

	if open {
		err = s.FirewallOpenPort(port, proto)
	} else {
		err = s.FirewallClosePort(port, proto)
	}
	if err == nil {
		return true, nil
	}
	// 入队失败（队列满且是新端口）时，这条意图既没执行也没排队——比普通
	// 失败严重得多，必须让调用方区分出来，而不能只报「动手失败」。
	if !s.markFirewallPending(port, proto, open) {
		return true, fmt.Errorf("%w: %v", ErrFirewallQueueFull, err)
	}
	log.Printf("[firewall] 端口 %d/%s %s失败，已加入重试队列: %v", port, proto, actionName(open), err)
	return true, err
}

// actionName 把意图转成日志用的动作名。
func actionName(open bool) string {
	if open {
		return "放行"
	}
	return "收回"
}

// portIntentValid 判断某端口的意图按数据库现状是否仍然成立。
//
// 这是每次动手前的必查项，防的是「旧意图关掉新隧道的端口」：
// 旧隧道删除后端口被新隧道复用，此时那条「收回 20001」的待办还在队列里，
// 照着执行就会把新隧道的规则一起关掉——用户看到的是「隧道莫名连不上」。
//
// 判定规则：端口当前应当处于什么状态，与本次意图一致才动手。
//   - 有活跃隧道占用 → 应当放行；意图是「收回」就作废。
//   - 没有活跃隧道占用 → 应当收回；意图是「放行」就作废。
//
// 第二个返回值是「读不出来」：这时**不动手也不作废**，由调用方排队重试。
// 宁可留着一条规则，也不要误关一条活跃隧道的端口。
func (s *Services) portIntentValid(port int, open bool) (bool, error) {
	var t model.Tunnel
	err := s.DB.Where("remote_port = ?", port).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 没有任何隧道占用这个端口：该关，不该开。
		return !open, nil
	}
	if err != nil {
		return false, err
	}
	return (t.Status == model.TunnelStatusActive) == open, nil
}

// PendingFirewallOps 返回仍在重试的端口操作（形如 "20001/tcp 待收回"），供管理页展示。
//
// 只含**还没到终态**的；已耗尽的由 FailedFirewallOps 单独展示——
// 两类东西的处置完全不同：前者等下一轮重试就行，后者必须管理员出手。
func (s *Services) PendingFirewallOps() []string {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	out := make([]string, 0, len(s.fwPending))
	for port, item := range s.fwPending {
		if item.exhausted {
			continue
		}
		action := "待收回"
		if item.open {
			action = "待放行"
		}
		out = append(out, fmt.Sprintf("%d/%s %s", port, item.proto, action))
	}
	sort.Strings(out)
	return out
}

// FirewallFailedOp 是一条重试已终止、等待人工处理的端口操作，供管理页展示。
type FirewallFailedOp struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Open     bool   `json:"open"`
	Attempts int    `json:"attempts"`
	LastErr  string `json:"last_err,omitempty"`
}

// FailedFirewallOps 返回已耗尽重试、保留待人工处理的端口操作。
//
// 这里只做快照，不重查数据库现状：终态记录的过时清理由重试循环
// 每轮做一次（见 retryPendingFirewall），展示层重复一遍只会让一次
// GET 也具备写语义。
func (s *Services) FailedFirewallOps() []FirewallFailedOp {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	out := make([]FirewallFailedOp, 0, len(s.fwPending))
	for port, item := range s.fwPending {
		if !item.exhausted {
			continue
		}
		out = append(out, FirewallFailedOp{
			Port:     port,
			Proto:    item.proto,
			Open:     item.open,
			Attempts: item.attempts,
			LastErr:  truncate(item.lastErr, 255),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// ClearFirewallFailed 清除一条已终止的失败记录。
//
// 管理员人工处理完（手工放行/关闭了端口、或确认那条规则本来就不存在）
// 之后调用。只允许清除终态记录：还在重试队列里的条目被清掉，
// 就等于替管理员取消了「后台说改好了、其实没改」的那件事本身。
func (s *Services) ClearFirewallFailed(port int) error {
	// 与重试循环同一把端口锁 + 锁序，避免清除与终态写入互相踩。
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()

	s.fwMu.Lock()
	item, ok := s.fwPending[port]
	s.fwMu.Unlock()
	if !ok || !item.exhausted {
		return fmt.Errorf("%w: 端口 %d 没有已终止的失败记录", ErrNotFound, port)
	}
	s.dropPending(port, item.gen)
	return nil
}
