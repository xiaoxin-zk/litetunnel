package service

import (
	"fmt"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type portProto struct {
	port  int
	proto string
}

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

func (s *Services) FirewallManualOpen(port int, proto string) error {
	be, err := s.requireWritableBackend()
	if err != nil {
		return err
	}
	if err := s.FirewallGuard().CheckAdd(port); err != nil {
		return err
	}
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()
	return be.AddPort(port, proto)
}

func (s *Services) FirewallManualClose(port int, proto string) error {
	be, err := s.requireWritableBackend()
	if err != nil {
		return err
	}
	if err := s.FirewallGuard().CheckRemove(port); err != nil {
		return err
	}
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
