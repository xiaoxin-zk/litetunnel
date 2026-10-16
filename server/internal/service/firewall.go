package service

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

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
	if _, isNone := be.(*firewall.None); isNone {
		return nil
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
	if _, isNone := be.(*firewall.None); isNone {
		return nil
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

// closePorts 逐个回收端口。
//
// 只记日志、不返回错误：调用方此刻已经删完数据了，让回收失败把
// 「删除成功」变成错误返回，只会让管理员以为没删掉而重复操作。
// 失败必须留痕，因为这类残留规则只能靠人工清理。
func (s *Services) closePorts(ports []portProto) {
	for _, p := range ports {
		if err := s.FirewallClosePort(p.port, p.proto); err != nil {
			log.Printf("[firewall] 回收端口 %d/%s 失败，需要人工清理: %v", p.port, p.proto, err)
		}
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
		if err := s.FirewallOpenPort(tunnels[i].RemotePort, ProtoOfTunnel(tunnels[i].Type)); err != nil {
			failed++
			continue
		}
		ok++
	}
	log.Printf("[firewall] 规则对齐完成：%d 个端口已放行，%d 个失败（后端 %s）", ok, failed, be.Name())
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

	Error string `json:"error,omitempty"`
}

// FirewallStatusOf 采集防火墙运行态。
func (s *Services) FirewallStatusOf() *FirewallStatus {
	st := &FirewallStatus{
		Enabled:   s.Settings.Bool(KeyFirewallEnabled),
		AutoOpen:  s.Settings.Bool(KeyFirewallAutoOpen),
		Protected: s.FirewallGuard().Protected(),
		PoolStart: s.Cfg.PortRangeStart,
		PoolEnd:   s.Cfg.PortRangeEnd,
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

// StartFirewallReconciler 在启动时对齐一次规则。
//
// 延迟几秒执行：等待 frps 与数据库就绪，避免启动瞬间的误判。
func (s *Services) StartFirewallReconciler() {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		s.ReconcileFirewall()
	}()
}
