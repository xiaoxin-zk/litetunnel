package service

import (
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
// 每次调用都重新探测，而不是缓存一个实例：
//   - 探测成本极低（只是判断命令是否存在）
//   - 管理员可能刚装上 firewalld 或改了后端偏好，缓存会导致配置不生效
func (s *Services) FirewallBackend() firewall.Backend {
	if !s.Settings.Bool(KeyFirewallEnabled) {
		return firewall.NewNone("防火墙控制未启用")
	}
	return firewall.Detect(s.Settings.Get(KeyFirewallBackend))
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
	return u
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
