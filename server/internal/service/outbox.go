package service

import (
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type TunnelMutationResult struct {
	DBUpdated       bool   `json:"db_updated"`
	FirewallPending bool   `json:"firewall_pending"`
	Warning         string `json:"warning,omitempty"`
}

type portIntent struct {
	port  int
	proto string
	open  bool
	gen   int64
}

func nextFirewallGenTx(tx *gorm.DB) (int64, error) {
	var seq model.FirewallSeq
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&seq, 1).Error; err != nil {
		return 0, err
	}
	if err := tx.Model(&model.FirewallSeq{}).Where("id = ?", 1).
		Update("next", seq.Next+1).Error; err != nil {
		return 0, err
	}
	return seq.Next, nil
}

func firewallIntentTx(tx *gorm.DB, port int, proto string, open bool) (int64, error) {
	if port <= 0 {
		return 0, nil
	}
	gen, err := nextFirewallGenTx(tx)
	if err != nil {
		return 0, fmt.Errorf("取防火墙待办代次失败（端口 %d）: %w", port, err)
	}
	rec := model.FirewallPending{
		Port:       port,
		Proto:      proto,
		Open:       open,
		Generation: gen,
	}
	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "port"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"proto", "open", "attempts", "exhausted", "generation", "last_err",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr("excluded.generation > lt_firewall_pending.generation OR (excluded.generation = lt_firewall_pending.generation AND excluded.attempts >= lt_firewall_pending.attempts)"),
		}},
	}).Create(&rec).Error; err != nil {
		return 0, fmt.Errorf("防火墙意图落库失败（端口 %d），已回滚本次变更: %w", port, err)
	}
	return gen, nil
}

func (s *Services) adoptPendingIntent(port int, proto string, open bool, gen int64) {
	if port <= 0 || gen <= 0 {
		return
	}
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	if s.fwPending == nil {
		s.fwPending = map[int]pendingFW{}
	}
	prev, exists := s.fwPending[port]
	if exists && gen <= prev.gen {
		return
	}
	attempts := 0
	if exists && prev.open == open && prev.proto == proto {
		attempts = prev.attempts
	}
	s.fwPending[port] = pendingFW{open: open, proto: proto, attempts: attempts, gen: gen}
}

func (s *Services) executePortIntentsAfterCommit(intents []portIntent) (pending int, fatal error, warnings []string) {
	for _, it := range intents {
		if it.port <= 0 {
			continue
		}
		s.adoptPendingIntent(it.port, it.proto, it.open, it.gen)

		_, err := s.applyPortIntent(it.port, it.proto, it.open)
		if err == nil {
			s.dropPending(it.port, it.gen)
			continue
		}
		if errors.Is(err, ErrFirewallStateUnknown) {
			pending++
			warnings = append(warnings, fmt.Sprintf("端口 %d/%s 当前状态未知，已保留待重试", it.port, it.proto))
			continue
		}

		pending++
		msg := fmt.Sprintf("端口 %d/%s %s失败，已进入重试队列：%v",
			it.port, it.proto, actionName(it.open), err)
		log.Printf("[outbox] %s", msg)
		warnings = append(warnings, msg)
		if errors.Is(err, ErrFirewallQueueFull) || errors.Is(err, ErrFirewallQueueUnavailable) {
			if fatal == nil {
				fatal = err
			}
		}
	}
	return pending, fatal, warnings
}

func firewallPendingWarning(warnings []string, count int) string {
	if count <= 0 {
		return ""
	}
	if len(warnings) > 0 {
		return "数据库已更新，但防火墙规则尚未生效（" + warnings[0] + "）；后台会自动重试，无需重复操作"
	}
	return "数据库已更新，但防火墙规则尚未生效；后台会自动重试，无需重复操作"
}

func tunnelMutationResult(pending int, warnings []string) TunnelMutationResult {
	return TunnelMutationResult{
		DBUpdated:       true,
		FirewallPending: pending > 0,
		Warning:         firewallPendingWarning(warnings, pending),
	}
}
