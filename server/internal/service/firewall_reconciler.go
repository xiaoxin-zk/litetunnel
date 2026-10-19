package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) retryPendingFirewall() int {
	s.fwMu.Lock()
	ports := make([]int, 0, len(s.fwPending))
	for port := range s.fwPending {
		ports = append(ports, port)
	}
	s.fwMu.Unlock()

	waiting := 0
	for _, port := range ports {
		pl := s.portLock(port)
		pl.Lock()

		s.fwMu.Lock()
		item, ok := s.fwPending[port]
		s.fwMu.Unlock()
		if !ok {
			pl.Unlock()
			continue
		}

		if item.exhausted {
			valid, verr := s.portIntentValid(port, item.open)
			if verr == nil && !valid {
				s.dropPending(port, item.gen)
				pl.Unlock()
				log.Printf("[firewall] 端口 %d 的终态失败记录已过时（当前状态与%s不符），已作废",
					port, actionName(item.open))
				continue
			}
			pl.Unlock()
			continue
		}

		valid, verr := s.portIntentValid(port, item.open)
		if verr != nil {
			pl.Unlock()
			continue
		}
		if !valid {
			s.dropPending(port, item.gen)
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
				item.exhausted = true
				s.setPendingIfCurrent(port, item)
				if perr := s.persistPending(port, item); perr != nil {
					log.Printf("[firewall] 端口 %d 的终态未能落库（重启后仍会重试一轮）: %v", port, perr)
				}
				pl.Unlock()
				log.Printf("[firewall] 端口 %d 连续 %d 次处理失败，已停止自动重试并将保留在管理页（最后错误: %v）",
					port, item.attempts, err)
				continue
			}
			s.setPendingIfCurrent(port, item)
			if perr := s.persistPending(port, item); perr != nil {
				log.Printf("[firewall] 端口 %d 的重试计数未能落库: %v", port, perr)
			}
			pl.Unlock()
			continue
		}

		s.dropPending(port, item.gen)
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

	ok, failed := 0, 0
	for i := range tunnels {
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

func (s *Services) StartFirewallReconciler(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		start := time.NewTimer(3 * time.Second)
		select {
		case <-start.C:
		case <-ctx.Done():
			start.Stop()
			return
		}

		s.loadPendingFirewall()

		aligned := false
		for {
			if ctx.Err() != nil {
				return
			}

			enabled := s.Settings.Bool(KeyFirewallEnabled)
			if !enabled {
				aligned = false
			} else {
				if !aligned {
					aligned = s.ReconcileFirewall()
				}
				if n := s.retryPendingFirewall(); n > 0 {
					log.Printf("[firewall] 仍有 %d 个端口操作待处理，将在下个周期继续重试", n)
				}
			}

			timer := time.NewTimer(firewallRetryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-s.fwKick:
				timer.Stop()
				aligned = false
			}
		}
	}()
	return done
}
