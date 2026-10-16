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
	open     bool
	proto    string
	attempts int
	lastErr  string
}

const (
	// firewallRetryInterval 是重试待处理端口操作的间隔。
	firewallRetryInterval = 2 * time.Minute
	// pendingFWMaxAttempts 是同一端口的最大重试次数。
	//
	// 必须有上限：有些失败是**永久性**的（端口在保护列表里、不在端口池内），
	// 无限重试只会每两分钟刷一次同样的日志。到上限后放弃并明确要求人工清理。
	pendingFWMaxAttempts = 5
	// pendingFWLimit 是待重试队列的长度上限，防止异常情况下无限增长。
	pendingFWLimit = 512
)

// markFirewallPending 记下一条待重试的端口操作。
func (s *Services) markFirewallPending(port int, proto string, open bool) {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	if _, ok := s.fwPending[port]; ok {
		// 已有记录时**覆盖**为最新意图（而不是保留旧的）：见 pendingFW 的注释。
		s.fwPending[port] = pendingFW{open: open, proto: proto}
		return
	}
	if len(s.fwPending) >= pendingFWLimit {
		log.Printf("[firewall] 待处理端口操作已达上限 %d，端口 %d 不再进入重试队列，需要人工清理",
			pendingFWLimit, port)
		return
	}
	s.fwPending[port] = pendingFW{open: open, proto: proto}
}

// applyPortIntent 执行一次端口操作；失败时记入待重试队列。
//
// 失败不能只写日志：数据库状态已经改了、接口也返回了成功，而规则没变。
// 启动时的规则对齐只补开不收回，放行失败更是没有任何地方会再尝试，
// 所以两种失败都必须排队重试。
func (s *Services) applyPortIntent(port int, proto string, open bool) {
	if port <= 0 {
		return
	}
	var err error
	if open {
		err = s.FirewallOpenPort(port, proto)
	} else {
		err = s.FirewallClosePort(port, proto)
	}
	if err == nil {
		return
	}
	s.markFirewallPending(port, proto, open)
	action := "收回"
	if open {
		action = "放行"
	}
	log.Printf("[firewall] 端口 %d/%s %s失败，已加入重试队列: %v", port, proto, action, err)
}

// portIntentValid 判断某端口的意图按数据库现状是否仍然成立。
//
// 这是重试前的必查项，防的是「旧任务关掉新隧道的端口」：
// 旧隧道删除后端口被新隧道复用，此时那条「收回 20001」的待办还在队列里，
// 照着执行就会把新隧道的规则一起关掉——用户看到的是「隧道莫名连不上」。
//
// 判定规则：端口当前应当处于什么状态，与待办记录的意图一致才动手。
//   - 有活跃隧道占用 → 应当放行；待办是「收回」就作废。
//   - 没有活跃隧道占用 → 应当收回；待办是「放行」就作废。
//
// 读不出隧道时返回 false（不动手）：宁可留着一条规则，也不要误关
// 一条活跃隧道的端口。
func (s *Services) portIntentValid(port int, open bool) bool {
	var t model.Tunnel
	err := s.DB.Where("remote_port = ?", port).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 没有任何隧道占用这个端口：该关，不该开。
		return !open
	}
	if err != nil {
		return false
	}
	return (t.Status == model.TunnelStatusActive) == open
}

// PendingFirewallOps 返回待处理的端口操作（形如 "20001/tcp 待收回"），供管理页展示。
func (s *Services) PendingFirewallOps() []string {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	out := make([]string, 0, len(s.fwPending))
	for port, item := range s.fwPending {
		action := "待收回"
		if item.open {
			action = "待放行"
		}
		out = append(out, fmt.Sprintf("%d/%s %s", port, item.proto, action))
	}
	sort.Strings(out)
	return out
}

// retryPendingFirewall 重试所有待处理的端口操作，返回仍在等待的数量。
//
// 只处理「我们自己记下来的」端口，不做全表扫描：收回比放行危险得多，
// 扫全表去猜哪些规则是多余的，很容易把管理员自己的连接也关掉
// （这也是 ReconcileFirewall 刻意不收回端口的原因）。
func (s *Services) retryPendingFirewall() int {
	s.fwMu.Lock()
	ports := make([]int, 0, len(s.fwPending))
	for port := range s.fwPending {
		ports = append(ports, port)
	}
	s.fwMu.Unlock()

	for _, port := range ports {
		s.fwMu.Lock()
		item, ok := s.fwPending[port]
		s.fwMu.Unlock()
		if !ok {
			continue
		}

		// 意图过时（端口被新隧道复用、或隧道已经删掉）就直接作废，
		// 绝不动手——这正是「旧任务关掉新隧道端口」的防线。
		if !s.portIntentValid(port, item.open) {
			s.fwMu.Lock()
			delete(s.fwPending, port)
			s.fwMu.Unlock()
			log.Printf("[firewall] 端口 %d 的待办已过时（当前状态与意图不符），已作废，未做任何操作", port)
			continue
		}

		var err error
		if item.open {
			err = s.FirewallOpenPort(port, item.proto)
		} else {
			err = s.FirewallClosePort(port, item.proto)
		}
		if err != nil {
			s.fwMu.Lock()
			item.attempts++
			item.lastErr = err.Error()
			if item.attempts >= pendingFWMaxAttempts {
				delete(s.fwPending, port)
				s.fwMu.Unlock()
				log.Printf("[firewall] 端口 %d 连续 %d 次处理失败，放弃自动重试，需要人工清理（最后错误: %v）",
					port, item.attempts, err)
				continue
			}
			s.fwPending[port] = item
			s.fwMu.Unlock()
			continue
		}

		s.fwMu.Lock()
		delete(s.fwPending, port)
		s.fwMu.Unlock()
		action := "收回"
		if item.open {
			action = "放行"
		}
		log.Printf("[firewall] 端口 %d/%s 已补%s（此前失败 %d 次）", port, item.proto, action, item.attempts)
	}

	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	return len(s.fwPending)
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
func (s *Services) FirewallManualClose(port int, proto string) error {
	be, err := s.requireWritableBackend()
	if err != nil {
		return err
	}
	if err := s.FirewallGuard().CheckRemove(port); err != nil {
		return err
	}
	return be.RemovePort(port, proto)
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
func (s *Services) ReconcileFirewall() {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return
	}
	be := s.FirewallBackend()
	if _, isNone := be.(*firewall.None); isNone {
		log.Printf("[firewall] 未检测到可用的防火墙后端，跳过规则对齐")
		return
	}

	var tunnels []model.Tunnel
	if err := s.DB.Where("status = ? AND remote_port > 0", model.TunnelStatusActive).
		Find(&tunnels).Error; err != nil {
		log.Printf("[firewall] 读取隧道列表失败，跳过规则对齐: %v", err)
		return
	}

	ok, failed := 0, 0
	for i := range tunnels {
		// 走 applyPortIntent 而不是直接 FirewallOpenPort：对齐时失败的端口
		// 同样要进重试队列。否则 helper 恰好在这一刻不可用，所有端口都要
		// 等到下次重启才可能被放行。
		if err := s.FirewallOpenPort(tunnels[i].RemotePort, ProtoOfTunnel(tunnels[i].Type)); err != nil {
			failed++
			s.markFirewallPending(tunnels[i].RemotePort, ProtoOfTunnel(tunnels[i].Type), true)
			continue
		}
		ok++
	}
	log.Printf("[firewall] 规则对齐完成：%d 个端口已放行，%d 个失败（失败项已进入重试队列，后端 %s）", ok, failed, be.Name())
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
	// Free 是仍可分配的端口数量
	Free int `json:"free"`
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
	listening := firewall.ListeningPortSet()
	for p := u.PoolStart; p <= u.PoolEnd; p++ {
		key := strconv.Itoa(p)
		if listening["tcp|"+key] || listening["udp|"+key] {
			u.SystemListening = append(u.SystemListening, p)
		}
	}

	var used []int
	if err := s.DB.Model(&model.Tunnel{}).
		Where("remote_port > 0").Pluck("remote_port", &used).Error; err == nil {
		for _, p := range used {
			if p >= u.PoolStart && p <= u.PoolEnd {
				u.Allocated = append(u.Allocated, p)
			}
		}
	}

	u.Free = u.Total - len(u.Reserved) - len(u.SystemListening) - len(u.Allocated)
	if u.Free < 0 {
		u.Free = 0
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
	if u.Total > 0 && u.Free*100/u.Total < 10 {
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

// StartFirewallReconciler 在启动时对齐一次规则，之后持续重试失败的端口收回。
//
// 延迟几秒执行：等待 frps 与数据库就绪，避免启动瞬间的误判。
func (s *Services) StartFirewallReconciler() {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		s.ReconcileFirewall()

		// 之后只重试「失败的收回」，不再周期性做整表对齐：
		// 对齐会给每条活跃隧道都发一次 helper 请求，没必要反复做，
		// 而失败的收回才是会一直悬着的那件事。
		ticker := time.NewTicker(firewallRetryInterval)
		defer ticker.Stop()
		for range ticker.C {
			if n := s.retryPendingFirewall(); n > 0 {
				log.Printf("[firewall] 仍有 %d 个端口操作待处理，将在下个周期继续重试", n)
			}
		}
	}()
}
