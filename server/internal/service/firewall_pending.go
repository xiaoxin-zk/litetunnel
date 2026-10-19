package service

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type pendingFW struct {
	open      bool
	proto     string
	attempts  int
	lastErr   string
	exhausted bool
	gen       int64
}

const (
	firewallRetryInterval = 2 * time.Minute
	pendingFWMaxAttempts  = 5
	pendingFWLimit        = 512
)

func (s *Services) nextFirewallGen() (int64, error) {
	var next int64
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var seq model.FirewallSeq
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&seq, 1).Error; err != nil {
			return err
		}
		next = seq.Next
		return tx.Model(&model.FirewallSeq{}).Where("id = ?", 1).
			Update("next", seq.Next+1).Error
	})
	return next, err
}

func (s *Services) markFirewallPending(port int, proto string, open bool) error {
	gen, err := s.nextFirewallGen()
	if err != nil {
		log.Printf("[firewall] 获取待办代次失败（端口 %d），本次意图无法登记: %v", port, err)
		return fmt.Errorf("%w: %v", ErrFirewallQueueUnavailable, err)
	}

	s.fwMu.Lock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	prev, exists := s.fwPending[port]
	if exists && gen <= prev.gen {
		s.fwMu.Unlock()
		return nil
	}
	attempts := 0
	if exists {
		if prev.open == open && prev.proto == proto {
			attempts = prev.attempts
		}
	} else if len(s.fwPending)+s.fwReserved >= pendingFWLimit {
		s.fwMu.Unlock()
		log.Printf("[firewall] 待处理端口操作已达上限 %d，端口 %d 不再进入重试队列，需要人工清理",
			pendingFWLimit, port)
		return ErrFirewallQueueFull
	} else {
		s.fwReserved++
		defer func() {
			s.fwMu.Lock()
			s.fwReserved--
			s.fwMu.Unlock()
		}()
	}
	item := pendingFW{open: open, proto: proto, attempts: attempts, gen: gen}
	s.fwMu.Unlock()

	if err := s.persistPending(port, item); err != nil {
		return fmt.Errorf("%w: %v", ErrFirewallQueueUnavailable, err)
	}

	s.fwMu.Lock()
	if cur, ok := s.fwPending[port]; ok && cur.gen >= gen {
		s.fwMu.Unlock()
		return nil
	}
	s.fwPending[port] = item
	s.fwMu.Unlock()
	return nil
}

func (s *Services) persistPending(port int, item pendingFW) error {
	rec := model.FirewallPending{
		Port:       port,
		Proto:      item.proto,
		Open:       item.open,
		Attempts:   item.attempts,
		Exhausted:  item.exhausted,
		Generation: item.gen,
		LastErr:    truncate(item.lastErr, 255),
	}
	if err := s.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"proto", "open", "attempts", "exhausted", "generation", "last_err",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr("excluded.generation > lt_firewall_pending.generation OR (excluded.generation = lt_firewall_pending.generation AND excluded.attempts >= lt_firewall_pending.attempts)"),
		}},
	}).Create(&rec).Error; err != nil {
		log.Printf("[firewall] 待办落库失败（端口 %d）: %v", port, err)
		return err
	}
	return nil
}

func (s *Services) dropPending(port int, gen int64) {
	if err := s.DB.Where("port = ? AND generation = ?", port, gen).
		Delete(&model.FirewallPending{}).Error; err != nil {
		log.Printf("[firewall] 清除待办记录失败（端口 %d，保留内存项继续重试）: %v", port, err)
		return
	}

	s.fwMu.Lock()
	if cur, ok := s.fwPending[port]; ok && cur.gen == gen {
		delete(s.fwPending, port)
	}
	s.fwMu.Unlock()
}

func (s *Services) setPendingIfCurrent(port int, item pendingFW) bool {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	cur, ok := s.fwPending[port]
	if !ok || cur.gen != item.gen {
		return false
	}
	s.fwPending[port] = item
	return true
}

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
	loaded := 0
	for _, r := range recs {
		if len(s.fwPending) >= pendingFWLimit && !hasPendingLocked(s.fwPending, r.Port) {
			continue
		}
		if cur, ok := s.fwPending[r.Port]; ok && cur.gen > r.Generation {
			continue
		}
		s.fwPending[r.Port] = pendingFW{
			open: r.Open, proto: r.Proto, attempts: r.Attempts, lastErr: r.LastErr,
			exhausted: r.Exhausted, gen: r.Generation,
		}
		loaded++
	}
	n := len(s.fwPending)
	s.fwMu.Unlock()
	if loaded < len(recs) {
		log.Printf("[firewall] 从数据库恢复了 %d 条待处理的端口操作（共 %d 条，其余 %d 条超出队列上限 %d，未恢复，需人工核对）",
			n, len(recs), len(recs)-loaded, pendingFWLimit)
		return
	}
	log.Printf("[firewall] 从数据库恢复了 %d 条待处理的端口操作，将继续重试", n)
}

func hasPendingLocked(m map[int]pendingFW, port int) bool {
	_, ok := m[port]
	return ok
}

func (s *Services) applyPortIntent(port int, proto string, open bool) (acted bool, err error) {
	if port <= 0 {
		return false, nil
	}
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()
	return s.applyPortIntentLocked(port, proto, open)
}

func (s *Services) applyPortIntentLocked(port int, proto string, open bool) (acted bool, err error) {
	if port <= 0 {
		return false, nil
	}

	valid, verr := s.portIntentValid(port, open)
	if verr != nil {
		if perr := s.markFirewallPending(port, proto, open); perr != nil {
			return false, perr
		}
		log.Printf("[firewall] 无法确认端口 %d 的当前状态，本次不动手、已加入重试队列: %v", port, verr)
		return false, ErrFirewallStateUnknown
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
	if perr := s.markFirewallPending(port, proto, open); perr != nil {
		return true, fmt.Errorf("%w: %v", perr, err)
	}
	log.Printf("[firewall] 端口 %d/%s %s失败，已加入重试队列: %v", port, proto, actionName(open), err)
	return true, err
}

func actionName(open bool) string {
	if open {
		return "放行"
	}
	return "收回"
}

func (s *Services) portIntentValid(port int, open bool) (bool, error) {
	var t model.Tunnel
	err := s.DB.Where("remote_port = ?", port).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return !open, nil
	}
	if err != nil {
		return false, err
	}
	return (t.Status == model.TunnelStatusActive) == open, nil
}

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

type FirewallFailedOp struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Open     bool   `json:"open"`
	Attempts int    `json:"attempts"`
	LastErr  string `json:"last_err,omitempty"`
}

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

func (s *Services) ClearFirewallFailed(port int) error {
	pl := s.portLock(port)
	pl.Lock()
	defer pl.Unlock()

	s.fwMu.Lock()
	item, ok := s.fwPending[port]
	s.fwMu.Unlock()
	if !ok || !item.exhausted {
		return fmt.Errorf("%w: 端口 %d 没有已终止的失败记录", ErrNotFound, port)
	}
	s.dropPending(port, item.gen)
	return nil
}
