package service

import (
	"fmt"
	"log"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func ProtoOfTunnel(tunnelType string) string {
	if strings.EqualFold(tunnelType, model.ProxyTypeUDP) {
		return "udp"
	}
	return "tcp"
}

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

var (
	scanListeningPorts = firewall.ScanListening
	listeningPortSet   = firewall.ListeningPortSet
)

func (s *Services) FirewallGuard() *firewall.Guard {
	return firewall.NewGuard(
		s.Settings.Get(KeyFirewallProtected),
		s.Cfg.PortRangeStart,
		s.Cfg.PortRangeEnd,
	)
}

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
		return fmt.Errorf("%w: %s", ErrFirewallUnavailable, n.Reason())
	}
	if err := be.AddPort(port, proto); err != nil {
		log.Printf("[firewall] 放行端口 %d/%s 失败: %v", port, proto, err)
		return err
	}
	log.Printf("[firewall] 已放行端口 %d/%s（后端 %s）", port, proto, be.Name())
	return nil
}

func (s *Services) FirewallClosePort(port int, proto string) error {
	if port <= 0 {
		return nil
	}
	if !s.Settings.Bool(KeyFirewallEnabled) || !s.Settings.Bool(KeyFirewallAutoClose) {
		return nil
	}
	if err := s.FirewallGuard().CheckRemove(port); err != nil {
		log.Printf("[firewall] 拒绝关闭端口 %d/%s: %v", port, proto, err)
		return nil
	}
	be := s.FirewallBackend()
	if n, isNone := be.(*firewall.None); isNone {
		return fmt.Errorf("%w: %s", ErrFirewallUnavailable, n.Reason())
	}
	if err := be.RemovePort(port, proto); err != nil {
		log.Printf("[firewall] 关闭端口 %d/%s 失败: %v", port, proto, err)
		return err
	}
	log.Printf("[firewall] 已收回端口 %d/%s（后端 %s）", port, proto, be.Name())
	return nil
}

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
