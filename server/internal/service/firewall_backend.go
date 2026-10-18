package service

import (
	"fmt"
	"log"
	"strings"

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

// 端口扫描的间接引用：生产环境就是 firewall 包的实现，没有额外分支；
// 测试用它们覆盖「扫描失败」这条路径——那是最容易静默退化的分支
// （失败被当成「没有端口被监听」，于是把系统占用的端口分配给用户）。
var (
	scanListeningPorts = firewall.ScanListening
	listeningPortSet   = firewall.ListeningPortSet
)

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
//
// 与放行对称：总开关 + 自动收回开关都开才会动手；自动收回关闭时返回 nil
// （跳过、不重试），删/停隧道仍成功，规则留给管理员手工清理。
func (s *Services) FirewallClosePort(port int, proto string) error {
	if port <= 0 {
		return nil
	}
	if !s.Settings.Bool(KeyFirewallEnabled) || !s.Settings.Bool(KeyFirewallAutoClose) {
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
