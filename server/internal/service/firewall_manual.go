package service

import (
	"fmt"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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
	// 与自动收回（applyPortIntent）使用同一把端口锁：否则「手工放行」可能与
	// 并发的一条「删除隧道 → 自动收回」交错，最终规则状态取决于时序。
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()
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
