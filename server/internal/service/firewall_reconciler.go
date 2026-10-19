package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/firewall"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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
				s.dropPending(port, item.gen)
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
				// 终态：记录保留（内存 + 落库），由管理页展示，
				// 管理员修完宿主机后手工处理或清除记录。
				// 不能直接删：删了之后这条「本该收回却一直开着」的端口
				// 就再也不会出现在任何界面上，只剩一行迟早被滚动掉的日志。
				item.exhausted = true
				s.fwMu.Lock()
				s.fwPending[port] = item
				s.fwMu.Unlock()
				if perr := s.persistPending(port, item); perr != nil {
					log.Printf("[firewall] 端口 %d 的终态未能落库（重启后仍会重试一轮）: %v", port, perr)
				}
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
// 返回值在协程退出时关闭，供关闭阶段等待（见 main）。
func (s *Services) StartFirewallReconciler(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		// 延迟几秒执行：等待 frps 与数据库就绪，避免启动瞬间的误判。
		// 用可取消的 timer 而不是 Sleep：收到退出信号时不必等这几秒。
		start := time.NewTimer(3 * time.Second)
		select {
		case <-start.C:
		case <-ctx.Done():
			start.Stop()
			return
		}

		// 恢复上次进程遗留的待办：它们在内存里丢了，但意图还在库里。
		s.loadPendingFirewall()

		aligned := false
		for {
			// 每轮先看退出信号：协调器会访问数据库与 helper，
			// 关闭之后继续跑只会在已关停的连接上刷错误日志。
			if ctx.Err() != nil {
				return
			}

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

			timer := time.NewTimer(firewallRetryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-s.fwKick:
				// 被设置变更唤醒：立刻重新判断（对齐标记为 false 时会做整表对齐）。
				timer.Stop()
				aligned = false
			}
		}
	}()
	return done
}
