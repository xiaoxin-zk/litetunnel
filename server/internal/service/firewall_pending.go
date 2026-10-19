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
	// gen 是这条意图的版本号，来自落库的单调序列（nextFirewallGen）；
	// 落库用 generation 做条件写。
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

// nextFirewallGen 从数据库序列取下一个防火墙待办代次。
//
// 用落库的单行序列而不是进程内计数器：多实例部署时每个进程从相同值起步，
// 会生成相同代次，>= 条件无法区分先后。序列在库里，天然全局单调。
//
// 取号不要求持 fwMu（见 markFirewallPending：先取号再拿锁，避免在锁内做
// 数据库 IO）；代次单调，写回内存时用代次比较保证新意图覆盖旧意图。
func (s *Services) nextFirewallGen() (int64, error) {
	var next int64
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var seq model.FirewallSeq
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&seq, 1).Error; err != nil {
			return err
		}
		next = seq.Next
		return tx.Model(&model.FirewallSeq{}).Where("id = ?", 1).
			Update("next", seq.Next+1).Error
	})
	return next, err
}

// markFirewallPending 记下一条待重试的端口操作（内存 + 落库）。
//
// 返回 error 表示**没有**入队，调用方必须据此明确报错，否则会出现
// 「隧道已启用、端口未放行、管理页也没有待办」的永久不一致。错误分两种：
//
//   - ErrFirewallQueueFull：队列已满且这是一个新端口，需要人工清理队列；
//   - ErrFirewallQueueUnavailable：取不到落库代次（数据库故障），需要查库。
func (s *Services) markFirewallPending(port int, proto string, open bool) error {
	// 先取号（一次数据库事务），再拿 fwMu：取号是 IO，放在锁内会让数据库
	// 变慢时阻塞所有防火墙意图操作。代次单调，写回内存时用代次比较保证
	// 「新意图覆盖旧意图」不依赖取锁顺序。
	gen, err := s.nextFirewallGen()
	if err != nil {
		log.Printf("[firewall] 获取待办代次失败（端口 %d），本次意图无法登记: %v", port, err)
		return fmt.Errorf("%w: %v", ErrFirewallQueueUnavailable, err)
	}

	s.fwMu.Lock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	prev, exists := s.fwPending[port]
	if exists && gen <= prev.gen {
		// 期间已有更新的意图写入（并发登记取号更晚、先拿到锁）：这条已过期，
		// 不能覆盖新意图。
		s.fwMu.Unlock()
		return nil
	}
	// 已有记录时**覆盖**为最新意图（而不是保留旧的）：见 pendingFW 的注释。
	//
	// 重试次数只在「动作与协议都没变」时继承：意图一变（放行↔收回、tcp↔udp），
	// 说明端口的世界变了（新隧道启用、旧的已删），新意图该有自己完整的一轮
	// 预算；沿用旧计数会让它第一次失败就再次被判为终态。同一意图的再次尝试
	// 不在此列，那正是上限要拦的。
	attempts := 0
	if exists {
		if prev.open == open && prev.proto == proto {
			attempts = prev.attempts
		}
	} else if len(s.fwPending)+s.fwReserved >= pendingFWLimit {
		s.fwMu.Unlock()
		log.Printf("[firewall] 待处理端口操作已达上限 %d，端口 %d 不再进入重试队列，需要人工清理",
			pendingFWLimit, port)
		return ErrFirewallQueueFull
	} else {
		// 占位：容量检查与落库之间有空窗，不占位的话多个端口能同时通过检查，
		// 一起落库之后突破上限。落库结束（无论成败）再归还。
		s.fwReserved++
		defer func() {
			s.fwMu.Lock()
			s.fwReserved--
			s.fwMu.Unlock()
		}()
	}
	item := pendingFW{open: open, proto: proto, attempts: attempts, gen: gen}
	s.fwMu.Unlock()

	// 先落库再写内存：反过来会留下「内存说有、库里没有」的假象。
	//
	// 落库失败时返回错误而不是只记日志：防火墙意图是「端口开着却没人知道
	// 为什么」的唯一线索，重启后内存那份就消失了。调用方据此明确失败，
	// 用户会看到「隧道启用但端口策略未下发」，而不是一个静默的不一致。
	//
	// IO 放在锁外：不该让建/删隧道排在数据库往返后面。
	if err := s.persistPending(port, item); err != nil {
		return fmt.Errorf("%w: %v", ErrFirewallQueueUnavailable, err)
	}

	s.fwMu.Lock()
	if cur, ok := s.fwPending[port]; ok && cur.gen >= gen {
		// 落库期间另一条更新的意图已经写入内存：本次不再覆盖。
		s.fwMu.Unlock()
		return nil
	}
	s.fwPending[port] = item
	s.fwMu.Unlock()
	return nil
}

// persistPending 把一条待办写入数据库，返回错误由调用方决定如何处理。
func (s *Services) persistPending(port int, item pendingFW) error {
	rec := model.FirewallPending{
		Port:       port,
		Proto:      item.proto,
		Open:       item.open,
		Attempts:   item.attempts,
		Exhausted:  item.exhausted,
		Generation: item.gen,
		LastErr:    truncate(item.lastErr, 255),
	}
	// 条件 upsert：只有「代次更高」（新意图覆盖旧意图）或「同代次且重试次数
	// 不倒退」（重试循环的状态写回）才覆盖。落库在锁外，旧意图的写回可能
	// 晚于新意图——无条件覆盖会让旧「收回」顶掉新「放行」；同代次写回不
	// 带 attempts 条件的话，多实例下旧的重试状态会覆盖新的。
	if err := s.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"proto", "open", "attempts", "exhausted", "generation", "last_err",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			// 条件写分两层：
			//   - 代次更高：新意图覆盖旧意图（markFirewallPending 每次取新号）；
			//   - 同代次且重试次数不倒退：重试循环用同一代次写回 attempts/
			//     last_err，多实例下旧的重试状态不能覆盖新的。
			gorm.Expr("excluded.generation > lt_firewall_pending.generation OR (excluded.generation = lt_firewall_pending.generation AND excluded.attempts >= lt_firewall_pending.attempts)"),
		}},
	}).Create(&rec).Error
	if err != nil {
		log.Printf("[firewall] 待办落库失败（端口 %d）: %v", port, err)
		return err
	}
	return nil
}

// dropPending 从内存与数据库里同时移除一条待办，但只在它仍是**同代**时。
//
// 旧任务的删除可能晚于新意图的登记：无条件按端口删会把新待办一起删掉，
// 重启后那条新意图就没了。版本号让删除只作用于「我要删的那代」。
func (s *Services) dropPending(port int, gen int64) {
	// 先删库、后删内存。
	//
	// 反过来时：库删除失败，内存那条已经没了——协调器不再重试它，只有重启
	// 读库才会回来。而「先删库」失败可以简单返回：内存项留着，下一轮重试
	// 会再走一遍（applyPortIntent 幂等），不会留下「规则没下发、也无人重试」
	// 的空洞。
	if err := s.DB.Where("port = ? AND generation = ?", port, gen).
		Delete(&model.FirewallPending{}).Error; err != nil {
		log.Printf("[firewall] 清除待办记录失败（端口 %d，保留内存项继续重试）: %v", port, err)
		return
	}

	s.fwMu.Lock()
	if cur, ok := s.fwPending[port]; ok && cur.gen == gen {
		delete(s.fwPending, port)
	}
	s.fwMu.Unlock()
}

// setPendingIfCurrent 把重试结果写回内存，只在「端口上仍是同一代意图」时。
//
// 重试循环虽然在自己的端口锁内完成动作，但**登记**并不都走那把锁：
// tunnel_batch 的批量建隧道只登记待办并唤醒协调器（注释里明确说明不取端口
// 锁）。于是旧代次的重试结果可能晚于新代次登记落进 map，把「放行」顶成
// 「收回」——内存里错一份，重启后还会从库里读回来继续执行。
//
// 返回 false 表示写入被丢弃（端口上已经是别的代次，或那条意图已经被清掉），
// 调用方无需做额外处理：该做的事已经由新意图负责。
func (s *Services) setPendingIfCurrent(port int, item pendingFW) bool {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	cur, ok := s.fwPending[port]
	if !ok || cur.gen != item.gen {
		return false
	}
	s.fwPending[port] = item
	return true
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
	loaded := 0
	for _, r := range recs {
		// 恢复也要受容量上限约束：库里的历史待办可能远超内存上限（异常期间
		// 累积、或多实例共用一个库），全量装入等于绕过 pendingFWLimit——
		// 内存涨上去，重试一轮扫的端口也变多，周期被拉长。
		//
		// 超出部分不静默丢：留一条日志说明「还有 N 条没有恢复」，运维可以在
		// 端口管理页按端口自查，而不是以为队列已经空了。
		if len(s.fwPending) >= pendingFWLimit && !hasPendingLocked(s.fwPending, r.Port) {
			continue
		}
		// 加载不是无条件覆盖：协调器是延迟 3 秒才起来读库的，这段时间 HTTP
		// 服务已经在跑，新建/停用隧道会先往内存里写意图。无条件覆盖会把
		// 它们换成库里的旧记录——那条新意图既不执行、也不再被展示。
		// 只接受代次不低于内存现值的记录（代次单调，等价于「不许倒退」）。
		if cur, ok := s.fwPending[r.Port]; ok && cur.gen > r.Generation {
			continue
		}
		s.fwPending[r.Port] = pendingFW{
			open: r.Open, proto: r.Proto, attempts: r.Attempts, lastErr: r.LastErr,
			exhausted: r.Exhausted, gen: r.Generation,
		}
		loaded++
	}
	n := len(s.fwPending)
	s.fwMu.Unlock()
	if loaded < len(recs) {
		log.Printf("[firewall] 从数据库恢复了 %d 条待处理的端口操作（共 %d 条，其余 %d 条超出队列上限 %d，未恢复，需人工核对）",
			n, len(recs), len(recs)-loaded, pendingFWLimit)
		return
	}
	log.Printf("[firewall] 从数据库恢复了 %d 条待处理的端口操作，将继续重试", n)
}

// hasPendingLocked 报告该端口是否已在待办表里（调用方须持有 fwMu）。
func hasPendingLocked(m map[int]pendingFW, port int) bool {
	_, ok := m[port]
	return ok
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
		// 读不出状态：不动手，但记住意图等下一轮。队列满与队列不可用要分开
		// 报：后者是数据库故障，管理员该去查库而不是清队列。
		if perr := s.markFirewallPending(port, proto, open); perr != nil {
			return false, perr
		}
		log.Printf("[firewall] 无法确认端口 %d 的当前状态，本次不动手、已加入重试队列: %v", port, verr)
		return false, ErrFirewallStateUnknown
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
	// 入队失败时，这条意图既没执行也没排队——比普通失败严重得多，必须让
	// 调用方区分出来（队列满 vs 队列不可用），而不能只报「动手失败」。
	if perr := s.markFirewallPending(port, proto, open); perr != nil {
		return true, fmt.Errorf("%w: %v", perr, err)
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
