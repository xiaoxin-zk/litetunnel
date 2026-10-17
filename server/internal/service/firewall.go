package service

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// ProtoOfTunnel 返回隧道类型对应的防火墙协议。
//
// HTTP/HTTPS 隧道走 Caddy 的域名路由，不占用独立端口，
// 因此统一按 tcp 处理（它们的 RemotePort 恒为 0，不会被放行）。
func ProtoOfTunnel(tunnelType string) string {
	if strings.EqualFold(tunnelType, model.ProxyTypeUDP) {
		return "udp"
	}
	return "tcp"
}

// FirewallBackend 按当前设置构造防火墙后端。
//
// # 只有 helper 一条路
//
// 面板**不持有任何防火墙写能力**：容器里没有 iptables、没有 NET_ADMIN，
// 代码里也没有本地执行路径。所有写操作都转发给宿主机上的 lt-fw helper。
//
// helper 不可用时返回 None（即「什么都不做」），而不是退回本地执行——
// 那条路径已经不存在，也不应该存在：一旦容器能被授予 NET_ADMIN，
// 面板被攻破的后果就从「服务不可用」升级为「整台主机的防火墙失守」。
//
// 每次调用都重新探测而不是缓存：helper 可能刚被重启，缓存会让面板
// 在十几分钟内持续报「不可达」。
func (s *Services) FirewallBackend() firewall.Backend {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return firewall.NewNone("防火墙控制未启用")
	}

	h := firewall.NewHelperBackend(
		s.Settings.Get(KeyFirewallHelperAddr),
		s.Settings.Get(KeyFirewallHelperToken),
	)
	if !h.Available() {
		return firewall.NewNone(h.Reason())
	}
	return h
}

// FirewallGuard 按当前设置构造安全护栏。
func (s *Services) FirewallGuard() *firewall.Guard {
	return firewall.NewGuard(
		s.Settings.Get(KeyFirewallProtected),
		s.Cfg.PortRangeStart,
		s.Cfg.PortRangeEnd,
	)
}

// FirewallOpenPort 放行一个隧道端口。
//
// 三层开关依次判断：总开关 → 自动放行开关 → 护栏校验。
// 任何一层不通过都只是「不做」，而不是报错——隧道本身仍然可用，
// 只是需要管理员去安全组手工放行。
func (s *Services) FirewallOpenPort(port int, proto string) error {
	if port <= 0 {
		return nil
	}
	if !s.Settings.Bool(KeyFirewallEnabled) || !s.Settings.Bool(KeyFirewallAutoOpen) {
		return nil
	}
	if err := s.FirewallGuard().CheckAdd(port); err != nil {
		return err
	}
	be := s.FirewallBackend()
	if n, isNone := be.(*firewall.None); isNone {
		// 走到这里说明总开关是开的，只是 helper 不可用。
		// **不能返回 nil**：那等于告诉调用方「已经放行了」，于是这条规则
		// 永远不会被重试——隧道一直是启用状态，端口却没开，只能靠人工重扫
		// 或重启服务。返回错误，让调用方排队重试。
		return fmt.Errorf("%w: %s", ErrFirewallUnavailable, n.Reason())
	}
	if err := be.AddPort(port, proto); err != nil {
		log.Printf("[firewall] 放行端口 %d/%s 失败: %v", port, proto, err)
		return err
	}
	log.Printf("[firewall] 已放行端口 %d/%s（后端 %s）", port, proto, be.Name())
	return nil
}

// FirewallClosePort 收回一个隧道端口。
//
// 关闭比放行危险得多：配错会让管理员再也连不上服务器。
// 因此这里必须过 CheckRemove，而它内置了「保护端口」与「端口池范围」双重校验。
func (s *Services) FirewallClosePort(port int, proto string) error {
	if port <= 0 {
		return nil
	}
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return nil
	}
	if err := s.FirewallGuard().CheckRemove(port); err != nil {
		// 拒绝关闭属于预期行为（例如管理员把某端口加进了保护列表），
		// 记一条日志即可，不应让删除隧道的操作因此失败。
		log.Printf("[firewall] 拒绝关闭端口 %d/%s: %v", port, proto, err)
		return nil
	}
	be := s.FirewallBackend()
	if n, isNone := be.(*firewall.None); isNone {
		// 同 FirewallOpenPort：总开关开着却拿不到后端，是**失败**而不是
		// 「无需处理」。返回 nil 会让这次收回既不生效也不入队重试。
		return fmt.Errorf("%w: %s", ErrFirewallUnavailable, n.Reason())
	}
	if err := be.RemovePort(port, proto); err != nil {
		log.Printf("[firewall] 关闭端口 %d/%s 失败: %v", port, proto, err)
		return err
	}
	log.Printf("[firewall] 已收回端口 %d/%s（后端 %s）", port, proto, be.Name())
	return nil
}

// portProto 是一个待回收的隧道端口。
type portProto struct {
	port  int
	proto string
}

// portsOfTunnels 把一批隧道映射成待回收的端口清单。
//
// 删除用户时要「先读端口、再删记录、最后回收」——顺序不能换：
// 记录一删，端口号就再也查不回来了，而防火墙规则会留在宿主机上。
// 启动时的规则对齐只负责「放行已有的」，刻意不清理孤立规则
// （那需要判断哪些是孤立的，误删会让管理员连不上机器）。
//
// 读取放在调用方的事务里（传 tx 进来），而不是用主连接单独查一遍：
// 事务外先读再删会漏掉「读完之后、删除之前」并发创建的隧道，
// 那些隧道的记录被删掉，端口却不在回收清单里。
func portsOfTunnels(tunnels []model.Tunnel) []portProto {
	out := make([]portProto, 0, len(tunnels))
	for i := range tunnels {
		out = append(out, portProto{
			port:  tunnels[i].RemotePort,
			proto: ProtoOfTunnel(tunnels[i].Type),
		})
	}
	return out
}

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
func (s *Services) markFirewallPending(port int, proto string, open bool) {
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
		return
	}
	item := pendingFW{open: open, proto: proto, attempts: attempts}
	s.fwPending[port] = item
	s.fwMu.Unlock()

	// 落库放在锁外：这是 IO，不该让建/删隧道的请求排在它后面。
	s.persistPending(port, item)
}

// persistPending 把一条待办写入数据库（写失败只记日志：内存里那份仍然有效，
// 只是这次重启后会丢——比让整个防火墙操作失败要好）。
func (s *Services) persistPending(port int, item pendingFW) {
	rec := model.FirewallPending{
		Port:      port,
		Proto:     item.proto,
		Open:      item.open,
		Attempts:  item.attempts,
		Exhausted: item.exhausted,
		LastErr:   truncate(item.lastErr, 255),
	}
	if err := s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{"proto", "open", "attempts", "exhausted", "last_err"}),
	}).Create(&rec).Error; err != nil {
		log.Printf("[firewall] 待办落库失败（端口 %d，重启后会丢失这条意图）: %v", port, err)
	}
}

// dropPending 从内存与数据库里同时移除一条待办。
func (s *Services) dropPending(port int) {
	s.fwMu.Lock()
	delete(s.fwPending, port)
	s.fwMu.Unlock()

	if err := s.DB.Where("port = ?", port).Delete(&model.FirewallPending{}).Error; err != nil {
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
			exhausted: r.Exhausted,
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
		s.markFirewallPending(port, proto, open)
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
	s.markFirewallPending(port, proto, open)
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
	s.dropPending(port)
	return nil
}

// retryPendingFirewall 重试所有待处理的端口操作，返回仍在等待的数量。
//
// 只处理「我们自己记下来的」端口，不做全表扫描：收回比放行危险得多，
// 扫全表去猜哪些规则是多余的，很容易把管理员自己的连接也关掉
// （这也是 ReconcileFirewall 刻意不收回端口的原因）。
//
// 返回值只数**还没到终态**的：已耗尽的不再重试，数量里也不含它们，
// 否则每轮日志都会报「仍有 N 个待处理」，而其中有些永远不会成功。
func (s *Services) retryPendingFirewall() int {
	s.fwMu.Lock()
	ports := make([]int, 0, len(s.fwPending))
	for port := range s.fwPending {
		ports = append(ports, port)
	}
	s.fwMu.Unlock()

	waiting := 0
	for _, port := range ports {
		// 整段临界区都在端口锁内：读意图 → 校验 → 执行 → 提交待办状态。
		//
		// # 为什么「提交待办状态」也必须在锁内
		//
		// 曾经是执行完就释放锁，再回头更新/删除待办。这段间隙里同一端口
		// 可能被写入**新意图**（例如刚被停用的隧道又被启用），旧重试随后
		// 把新意图覆盖掉或直接删掉——那条真正需要执行的放行就再也不会被
		// 重试了，规则与数据库状态长期不一致。
		//
		// 锁序固定为「端口锁 → fwMu」，与 applyPortIntent 一侧一致，
		// 不存在反向获取。
		pl := s.portLock(port)
		pl.Lock()

		s.fwMu.Lock()
		item, ok := s.fwPending[port]
		s.fwMu.Unlock()
		if !ok {
			pl.Unlock()
			continue
		}

		// 已到终态的不再动手，但**每轮都校验一次意图是否还有效**：
		// 端口可能已被新隧道复用、或隧道状态已经反过来，此时那条失败
		// 记录描述的事早已不复存在，继续展示只会误导管理员。校验发现
		// 过时就顺手作废；仍然有效就留着，等管理员处理。
		if item.exhausted {
			valid, verr := s.portIntentValid(port, item.open)
			if verr == nil && !valid {
				s.dropPending(port)
				pl.Unlock()
				log.Printf("[firewall] 端口 %d 的终态失败记录已过时（当前状态与%s不符），已作废",
					port, actionName(item.open))
				continue
			}
			pl.Unlock()
			continue
		}

		// 意图过时（端口被新隧道复用、或隧道已经删掉）就直接作废，
		// 绝不动手——这正是「旧任务关掉新隧道端口」的防线。
		valid, verr := s.portIntentValid(port, item.open)
		if verr != nil {
			// 读不出来：保留待办，下轮再试。
			pl.Unlock()
			continue
		}
		if !valid {
			s.dropPending(port)
			pl.Unlock()
			log.Printf("[firewall] 端口 %d 的待办已过时（当前状态与%s不符），已作废，未做任何操作",
				port, actionName(item.open))
			continue
		}

		var err error
		if item.open {
			err = s.FirewallOpenPort(port, item.proto)
		} else {
			err = s.FirewallClosePort(port, item.proto)
		}

		if err != nil {
			item.attempts++
			item.lastErr = err.Error()
			if item.attempts >= pendingFWMaxAttempts {
				// 终态：记录保留（内存 + 落库），由管理页展示，
				// 管理员修完宿主机后手工处理或清除记录。
				// 不能直接删：删了之后这条「本该收回却一直开着」的端口
				// 就再也不会出现在任何界面上，只剩一行迟早被滚动掉的日志。
				item.exhausted = true
				s.fwMu.Lock()
				s.fwPending[port] = item
				s.fwMu.Unlock()
				s.persistPending(port, item)
				pl.Unlock()
				log.Printf("[firewall] 端口 %d 连续 %d 次处理失败，已停止自动重试并将保留在管理页（最后错误: %v）",
					port, item.attempts, err)
				continue
			}
			s.fwMu.Lock()
			s.fwPending[port] = item
			s.fwMu.Unlock()
			// 重试次数也要落库：否则重启后计数归零，永久失败的端口
			// 会重新走满一轮上限，日志反复出现。
			s.persistPending(port, item)
			pl.Unlock()
			continue
		}

		s.dropPending(port)
		pl.Unlock()
		log.Printf("[firewall] 端口 %d/%s 已补%s（此前失败 %d 次）",
			port, item.proto, actionName(item.open), item.attempts)
	}

	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	for _, item := range s.fwPending {
		if !item.exhausted {
			waiting++
		}
	}
	return waiting
}

// closePorts 逐个回收端口。
//
// 不返回错误：调用方此刻已经删完数据了，让回收失败把「删除成功」
// 变成错误返回，只会让管理员以为没删掉而重复操作。
// 但失败不能只留一行日志——会进待重试队列，由后台反复尝试。
func (s *Services) closePorts(ports []portProto) {
	for _, p := range ports {
		s.applyPortIntent(p.port, p.proto, false)
	}
}

// FirewallManualOpen 管理员手工放行端口。
//
// 与 FirewallOpenPort 的区别在于「失败时的态度」：
//
//   - FirewallOpenPort 是自动路径。防火墙没配好就静默跳过是合理的——
//     不该因为防火墙配置不完整就让用户建不了隧道。
//
//   - 本函数是管理员明确点了按钮。必须如实反馈：否则界面提示「已放行」
//     而实际什么都没做，管理员会带着「端口已经开了」的错误认知去排查
//     为什么用户连不上——这是本模块最容易误导人的地方。
func (s *Services) FirewallManualOpen(port int, proto string) error {
	be, err := s.requireWritableBackend()
	if err != nil {
		return err
	}
	if err := s.FirewallGuard().CheckAdd(port); err != nil {
		return err
	}
	return be.AddPort(port, proto)
}

// FirewallManualClose 管理员手工关闭端口。
//
// 端口仍被**启用中**的隧道占用时拒绝关闭：全量对齐会按活跃隧道把它重新
// 放行（见 ReconcileFirewall），管理员看到的是「关掉了又自己开了」，还会
// 误以为防火墙坏了。要让端口真正关闭，先停用/删除对应的隧道。
func (s *Services) FirewallManualClose(port int, proto string) error {
	be, err := s.requireWritableBackend()
	if err != nil {
		return err
	}
	if err := s.FirewallGuard().CheckRemove(port); err != nil {
		return err
	}
	// 检查与关闭必须在该端口的锁内完成，与自动放行（applyPortIntent）
	// 使用同一把锁：否则「统计为 0 → 并发启用隧道 → 自动放行 → 手工关闭」
	// 会让最终状态变成「隧道启用但端口关闭」。
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()

	n, err := s.activeTunnelPortCount(port, proto)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: 端口 %d 仍有 %d 条启用中的隧道，全量对齐会自动把它重新放行；请先停用这些隧道", ErrInvalidParam, port, n)
	}
	return be.RemovePort(port, proto)
}

// activeTunnelPortCount 统计仍占用该端口的启用中隧道数。
//
// 全量对齐按「status = active 的隧道」放行端口，所以这里用同一口径判断：
// 只要还有活跃隧道占着，手工关闭就会被下一轮对齐撤销。
func (s *Services) activeTunnelPortCount(port int, proto string) (int64, error) {
	q := s.DB.Model(&model.Tunnel{}).
		Where("remote_port = ? AND status = ?", port, model.TunnelStatusActive)
	if proto == "tcp" || proto == "udp" {
		q = q.Where("type = ?", proto)
	}
	var n int64
	err := q.Count(&n).Error
	return n, err
}

// requireWritableBackend 取一个「确实能写」的后端，取不到时说明原因。
func (s *Services) requireWritableBackend() (firewall.Backend, error) {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return nil, fmt.Errorf("%w: 防火墙控制未启用，面板不会修改任何防火墙规则", ErrInvalidParam)
	}
	be := s.FirewallBackend()
	if n, ok := be.(*firewall.None); ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParam, n.Reason())
	}
	return be, nil
}

// ReconcileFirewall 让防火墙规则与当前隧道列表对齐。
//
// 做两件事：
//  1. 放行所有活跃隧道占用的端口（覆盖控制面重启、规则丢失等场景）；
//  2. 不主动收回任何端口——收回只由「删除隧道」触发。
//
// 第 2 点是有意为之：如果对齐时顺手收回，一旦读取隧道列表出错或
// 保护端口配置有误，就可能把管理员自己的连接也关掉。
// 少收回一条规则的代价远小于被锁在服务器外。
//
// 返回是否真的做了一次对齐：helper 不可用、读库失败等情况下返回 false，
// 调用方据此**下一轮再试**，而不是把它当成「已经对齐过了」——
// 否则 helper 恢复之后，那些端口要等到重启服务才会被放行。
func (s *Services) ReconcileFirewall() bool {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return false
	}
	be := s.FirewallBackend()
	if _, isNone := be.(*firewall.None); isNone {
		log.Printf("[firewall] 未检测到可用的防火墙后端，跳过规则对齐")
		return false
	}

	var tunnels []model.Tunnel
	if err := s.DB.Where("status = ? AND remote_port > 0", model.TunnelStatusActive).
		Find(&tunnels).Error; err != nil {
		log.Printf("[firewall] 读取隧道列表失败，跳过规则对齐: %v", err)
		return false
	}

	// 逐端口走 applyPortIntent，而不是直接 FirewallOpenPort：
	//
	//   - 它会取端口锁，并在锁内**重新确认该端口当前确实该放行**。这里拿到的
	//     活跃隧道列表只是某一刻的快照，逐条放行的过程中隧道可能已被停用或
	//     删除——照着快照放行，等于把一条已经不该开着的端口重新打开。
	//   - 放行失败的端口会进重试队列，不必等到下次重启。
	ok, failed := 0, 0
	for i := range tunnels {
		// acted 表示这次确实动了手（false 表示快照已过时或状态读不出来，
		// 两种情况都不该计入「已放行」）。
		acted, err := s.applyPortIntent(tunnels[i].RemotePort, ProtoOfTunnel(tunnels[i].Type), true)
		if !acted {
			continue
		}
		if err != nil {
			failed++
			continue
		}
		ok++
	}
	log.Printf("[firewall] 规则对齐完成：%d 个端口已放行，%d 个失败（失败项已进入重试队列，后端 %s）", ok, failed, be.Name())
	return true
}

// FirewallStatus 是管理页需要的防火墙运行态。
type FirewallStatus struct {
	Enabled   bool   `json:"enabled"`
	AutoOpen  bool   `json:"auto_open"`
	Backend   string `json:"backend"`
	Reason    string `json:"reason,omitempty"`
	Active    bool   `json:"active"`
	Protected []int  `json:"protected_ports"`
	PoolStart int    `json:"pool_start"`
	PoolEnd   int    `json:"pool_end"`

	// ManagedRules 是本面板专属链/表内的规则
	ManagedRules []firewall.Rule `json:"managed_rules"`
	// ExternalRules 是系统既有的规则，只读展示，避免管理员误判「没放行」
	ExternalRules []firewall.Rule `json:"external_rules"`
	// Listening 是当前主机实际监听的端口，用于识别哪些端口已被占用
	Listening []firewall.ListeningPort `json:"listening"`

	// PendingOps 是「本该放行/收回、但 helper 当时失败」的端口，正在后台重试。
	//
	// 必须显示出来：这些端口对应的隧道已经建好、停用或删除，界面上一片正常，
	// 但规则并没跟着变。不暴露这个列表的话，管理员没有任何线索知道
	// 「后台说改好了，其实没改」。
	PendingOps []string `json:"pending_ops,omitempty"`

	// FailedOps 是重试已耗尽、自动处理终止的端口操作。
	//
	// 这些比 PendingOps 更要紧：后台已经彻底不管它们了——该放行的端口
	// 永远没放行（用户的隧道连不上），该收回的端口永远开着（隧道早删了、
	// 规则还在）。以前它们到上限就被删掉，只剩一行日志，界面无从知晓。
	FailedOps []FirewallFailedOp `json:"failed_ops,omitempty"`

	Error string `json:"error,omitempty"`
}

// FirewallStatusOf 采集防火墙运行态。
func (s *Services) FirewallStatusOf() *FirewallStatus {
	st := &FirewallStatus{
		Enabled:    s.Settings.Bool(KeyFirewallEnabled),
		AutoOpen:   s.Settings.Bool(KeyFirewallAutoOpen),
		Protected:  s.FirewallGuard().Protected(),
		PoolStart:  s.Cfg.PortRangeStart,
		PoolEnd:    s.Cfg.PortRangeEnd,
		PendingOps: s.PendingFirewallOps(),
		FailedOps:  s.FailedFirewallOps(),
	}

	be := s.FirewallBackend()
	st.Backend = be.Name()
	if n, ok := be.(*firewall.None); ok {
		st.Reason = n.Reason()
	}

	if active, err := be.Status(); err == nil {
		st.Active = active
	}

	if rules, err := be.ListRules(); err == nil {
		for _, r := range rules {
			if r.Managed {
				st.ManagedRules = append(st.ManagedRules, r)
			} else {
				st.ExternalRules = append(st.ExternalRules, r)
			}
		}
	} else {
		st.Error = err.Error()
	}

	if ports, err := firewall.ScanListening(); err == nil {
		st.Listening = ports
	} else {
		// 扫不到不等于没有：把原因带出去，否则界面显示「0 个端口被占用」
		// 而实际只是这次没读成，管理员会据此误判端口池还很宽裕。
		if st.Error == "" {
			st.Error = "读取系统监听端口失败：" + err.Error()
		} else {
			st.Error += "；读取系统监听端口失败：" + err.Error()
		}
	}
	return st
}

// PortPoolUsage 描述端口池的使用情况，供管理页做可视化。
type PortPoolUsage struct {
	PoolStart int `json:"pool_start"`
	PoolEnd   int `json:"pool_end"`

	// Reserved 是管理端配置的保留端口（不分配）
	Reserved []int `json:"reserved"`
	// SystemListening 是系统实际占用且在端口池范围内的端口
	SystemListening []int `json:"system_listening"`
	// Allocated 是已分配给用户隧道的端口
	Allocated []int `json:"allocated"`
	// Free 是仍可分配的端口数量；FreeUnknown 为 true 时它没有意义。
	Free int `json:"free"`
	// FreeUnknown 表示「已分配端口读不出来」，空闲量因此无法计算。
	//
	// 读库失败时若仍然按「保留 + 系统占用」算一个数出来，管理页会显示一个
	// 明显偏高的可用量（把已经分配给用户的端口也算成空闲），甚至与「端口
	// 已经用完」的事实相反——比不显示更糟。此时 Free 置 0 并由这个标记
	// 表明「未知」，界面据此显示「未知」而不是 0。
	FreeUnknown bool `json:"free_unknown"`
	// AllocatedError 是读取已分配端口失败的原因（仅 FreeUnknown 时非空）。
	AllocatedError string `json:"allocated_error,omitempty"`
	// ListeningUnknown 表示「系统监听端口扫描失败」，系统占用列表因此不完整。
	//
	// 与 AllocatedError 同样必须标出来：少算系统占用会让空闲量偏高，
	// 而管理员可能据此把端口池调小、或误以为还有余量。
	ListeningUnknown bool `json:"listening_unknown"`
	// ListeningError 是扫描失败的原因（仅 ListeningUnknown 时非空）。
	ListeningError string `json:"listening_error,omitempty"`
	// Total 是端口池总容量
	Total int `json:"total"`

	// ---- 诊断信息 ----
	//
	// 这些字段回答的是「为什么端口分配了却连不上」。
	// 端口池配错不会在启动时报错，只在用户建隧道时表现为「连不上」，
	// 排查成本极高——所以把关键判断前置到这里。

	// EphemeralStart/End 是内核分配给出站连接的源端口范围。
	// 端口池与它重叠会导致偶发的绑定失败。
	EphemeralStart int `json:"ephemeral_start,omitempty"`
	EphemeralEnd   int `json:"ephemeral_end,omitempty"`
	// Advice 是端口池配置的建议与警告，为空表示未发现问题。
	Advice []string `json:"advice,omitempty"`
	// FirewallNeeded 说明当前是否需要启用防火墙控制。
	FirewallNeeded bool `json:"firewall_needed"`
	// FirewallNote 解释判断依据。
	FirewallNote string `json:"firewall_note,omitempty"`
}

// PortPoolUsageOf 统计端口池使用情况。
func (s *Services) PortPoolUsageOf() *PortPoolUsage {
	u := &PortPoolUsage{
		PoolStart: s.Cfg.PortRangeStart,
		PoolEnd:   s.Cfg.PortRangeEnd,
	}
	if u.PoolEnd < u.PoolStart {
		return u
	}
	u.Total = u.PoolEnd - u.PoolStart + 1

	reserved := ParsePortList(s.Settings.Get(KeyPortReserved))
	for p := range reserved {
		if p >= u.PoolStart && p <= u.PoolEnd {
			u.Reserved = append(u.Reserved, p)
		}
	}

	// 系统占用：只统计落在端口池范围内的，池外的不关心
	//
	// 扫描失败时同样不能按「没有端口被占用」继续算：那会让空闲量偏高，
	// 而实际可能一个端口都不剩。标记为未知，由界面明确展示。
	if listening, err := firewall.ListeningPortSet(); err != nil {
		u.ListeningUnknown = true
		u.ListeningError = err.Error()
	} else {
		for p := u.PoolStart; p <= u.PoolEnd; p++ {
			key := strconv.Itoa(p)
			if listening["tcp|"+key] || listening["udp|"+key] {
				u.SystemListening = append(u.SystemListening, p)
			}
		}
	}

	var used []int
	if err := s.DB.Model(&model.Tunnel{}).
		Where("remote_port > 0").Pluck("remote_port", &used).Error; err != nil {
		// 读不出来就**不能**给出空闲数：少了「已分配」这一项，算出来的
		// 可用量会明显偏高，管理页据此判断「端口还很宽裕」是危险的。
		u.FreeUnknown = true
		u.AllocatedError = err.Error()
	} else {
		for _, p := range used {
			if p >= u.PoolStart && p <= u.PoolEnd {
				u.Allocated = append(u.Allocated, p)
			}
		}
	}

	// 空闲数按**端口集合**去重：同一个端口可能既被保留、又在监听、还被分配
	// （端口池调小之后尤其常见），直接相减各列表长度会把它扣好几次，
	// 把 Free 算成负数再夹到 0——看起来「没有空闲端口」，实际还有。
	usedSet := make(map[int]struct{}, len(u.Reserved)+len(u.SystemListening)+len(u.Allocated))
	for _, p := range u.Reserved {
		usedSet[p] = struct{}{}
	}
	for _, p := range u.SystemListening {
		usedSet[p] = struct{}{}
	}
	for _, p := range u.Allocated {
		usedSet[p] = struct{}{}
	}
	if u.FreeUnknown || u.ListeningUnknown {
		// 任一来源缺失都算不出可信的空闲量（少算系统占用会偏高，少算已分配
		// 同样偏高）。数值没有意义，保持 0 避免老界面把它当成「已用完」之外
		// 的怪值；是否可信统一由 FreeUnknown 表达。
		u.FreeUnknown = true
		u.Free = 0
	} else {
		u.Free = u.Total - len(usedSet)
		if u.Free < 0 {
			u.Free = 0
		}
	}

	s.diagnosePortRange(u)
	return u
}

// diagnosePortRange 检查端口池配置并给出可执行的建议。
//
// 这里的判断只基于「能在本机无损获取」的信息：内核的出站端口范围、
// 实际监听的端口、以及面板自己的设置。
//
// **云安全组读不到**，所以只做提示而不下结论——
// 谎称「已放行」比不说更糟：管理员会以为配好了，直到用户报障。
func (s *Services) diagnosePortRange(u *PortPoolUsage) {
	// 1. 与内核出站端口范围重叠
	if lo, hi, err := firewall.LocalPortRange(); err == nil {
		u.EphemeralStart, u.EphemeralEnd = lo, hi
		if u.PoolStart <= hi && u.PoolEnd >= lo {
			u.Advice = append(u.Advice, fmt.Sprintf(
				"端口池 %d-%d 与内核的出站端口范围 %d-%d 重叠。"+
					"这会导致 frps 偶发绑定失败（目标端口正被一条出站连接占用），"+
					"表现为随机的隧道建立失败。建议把池上限压到 %d 以下。",
				u.PoolStart, u.PoolEnd, lo, hi, lo-1))
		}
	}

	// 2. 池内可用端口过少
	//
	// 空闲量未知时不能判断：按 Free=0 去算只会给出一条「仅剩 0 个」的
	// 假警报，而真实原因是这次读库失败。如实说明即可。
	if u.FreeUnknown {
		var reasons []string
		if u.AllocatedError != "" {
			reasons = append(reasons, "读取已分配端口失败："+u.AllocatedError)
		}
		if u.ListeningError != "" {
			reasons = append(reasons, "读取系统监听端口失败："+u.ListeningError)
		}
		u.Advice = append(u.Advice, fmt.Sprintf(
			"可用端口数无法确定（%s）。请稍后刷新；"+
				"这期间「已分配 / 系统占用」列表也可能不完整。",
			strings.Join(reasons, "；")))
	} else if u.Total > 0 && u.Free*100/u.Total < 10 {
		u.Advice = append(u.Advice, fmt.Sprintf(
			"端口池仅剩 %d 个可用端口（共 %d 个），新建隧道可能因无端口可用而失败",
			u.Free, u.Total))
	}

	// 3. 说明是否需要防火墙控制
	//
	// 面板读不到云安全组，也无法判断「主机防火墙是否真的在拦截」，
	// 所以这里只解释依赖关系，把结论留给管理员。
	if s.Settings.Bool(KeyFirewallEnabled) {
		u.FirewallNeeded = true
		u.FirewallNote = "已启用：面板会通过宿主机 helper 自动放行隧道端口"
	} else {
		u.FirewallNote = "未启用。只有在主机防火墙确实会拦截隧道端口时才需要开启；" +
			"若端口放行由云安全组负责、主机上未启用防火墙，保持关闭即可——" +
			"此时没有任何规则需要面板去操作。"
	}
}

// StartFirewallReconciler 常驻：对齐规则并持续重试失败的端口操作。
//
// # 为什么不能「启动时没开就直接返回」
//
// 防火墙开关是运行期可改的。以前这里在启动时读一次设置，关着就整个协程都不
// 启动——于是管理员中途在面板上打开防火墙后，既没有规则对齐，也没有任何
// worker 去重试失败的端口操作：已有的活跃隧道不会立刻放行，失败的任务也
// 一直躺着。要重启服务才生效，而这一点界面完全不会提示。
//
// 所以协程总是启动，开关在**每一轮循环里**重新判断：
//   - 关着 → 什么都不做（也不该动规则）；
//   - 刚打开 → 先做一次完整对齐，再进入常规重试。
//
// 除了定时轮询，设置页打开防火墙时会通过 KickFirewall 立刻唤醒一次，
// 不必等下一个周期。
func (s *Services) StartFirewallReconciler() {
	go func() {
		// 延迟几秒执行：等待 frps 与数据库就绪，避免启动瞬间的误判。
		time.Sleep(3 * time.Second)

		// 恢复上次进程遗留的待办：它们在内存里丢了，但意图还在库里。
		s.loadPendingFirewall()

		aligned := false
		for {
			enabled := s.Settings.Bool(KeyFirewallEnabled)
			if !enabled {
				// 关着的时候不碰规则；同时把「已对齐」标记清掉，
				// 这样下次打开时会重新对齐一次。
				aligned = false
			} else {
				if !aligned {
					// 只有**真的对齐成功**才记下：helper 不可用时返回 false，
					// 下一轮会再试——否则 helper 恢复后要等重启服务才生效。
					aligned = s.ReconcileFirewall()
				}
				if n := s.retryPendingFirewall(); n > 0 {
					log.Printf("[firewall] 仍有 %d 个端口操作待处理，将在下个周期继续重试", n)
				}
			}

			select {
			case <-time.After(firewallRetryInterval):
			case <-s.fwKick:
				// 被设置变更唤醒：立刻重新判断（对齐标记为 false 时会做整表对齐）。
				aligned = false
			}
		}
	}()
}
