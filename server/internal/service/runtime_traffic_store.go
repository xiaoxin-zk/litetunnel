package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const leaseTrafficCollector = "traffic-collector"

const trafficCollectLease = 2 * time.Minute

func (s *Services) acquireLease(name string, ttl time.Duration) (int64, bool) {
	now := time.Now()
	exp := now.Add(ttl)
	rec := model.RuntimeLease{Name: name, Holder: s.instanceID, ExpiresAt: exp, Gen: 1}
	if err := s.DB.Create(&rec).Error; err == nil {
		return rec.Gen, true
	}
	res := s.DB.Model(&model.RuntimeLease{}).
		Where("name = ? AND (expires_at < ? OR holder = ?)", name, now, s.instanceID).
		Updates(map[string]any{
			"holder":     s.instanceID,
			"expires_at": exp,
			"gen":        gorm.Expr("gen + 1"),
		})
	if res.Error != nil {
		log.Printf("[lease] 抢占租约 %s 失败: %v", name, res.Error)
		return 0, false
	}
	if res.RowsAffected != 1 {
		return 0, false
	}
	var lease model.RuntimeLease
	if err := s.DB.Where("name = ?", name).First(&lease).Error; err != nil {
		log.Printf("[lease] 读取租约 %s 代次失败: %v", name, err)
		return 0, false
	}
	return lease.Gen, true
}

func (s *Services) releaseLease(name string) {
	res := s.DB.Model(&model.RuntimeLease{}).
		Where("name = ? AND holder = ?", name, s.instanceID).
		Updates(map[string]any{
			"expires_at": time.Now().Add(-time.Second),
			"gen":        gorm.Expr("gen + 1"),
		})
	if res.Error != nil {
		log.Printf("[lease] 交还租约 %s 失败: %v", name, res.Error)
	}
}

var errLeaseLost = errors.New("采集租约已被其他实例接手")

type trafficFence struct {
	leaseGen     int64
	resetGens    map[uint]int64
	resetChanged map[uint]bool
}

func (s *Services) flushTraffic(
	tunnelDeltas map[uint]*tunnelDelta,
	userDeltas map[uint]int64,
	tunnelOwner map[uint]uint,
	nextStat map[string]trafficPair,
	seed bool,
	fence trafficFence,
) error {
	now := time.Now()
	today := now.Format("2006-01-02")

	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

	skipUsers := s.Runtime.takePendingTrafficResets()

	missedReset := make(map[uint]bool)
	committedGens := make(map[uint]int64, len(fence.resetGens))
	for uid, gen := range fence.resetGens {
		committedGens[uid] = gen
	}

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if fence.leaseGen != 0 {
			var lease model.RuntimeLease
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("name = ?", leaseTrafficCollector).First(&lease).Error; err != nil {
				return fmt.Errorf("%w: %v", errLeaseLost, err)
			}
			if lease.Holder != s.instanceID || lease.Gen != fence.leaseGen {
				return errLeaseLost
			}
		}

		for id, d := range tunnelDeltas {
			updates := map[string]any{}
			if d.online {
				updates["last_online_at"] = now
			}
			if !seed {
				if total := d.in + d.out; total > 0 {
					updates["traffic_used"] = gorm.Expr("traffic_used + ?", total)
				}
			}
			if len(updates) == 0 {
				continue
			}
			if err := tx.Model(&model.Tunnel{}).Where("id = ?", id).Updates(updates).Error; err != nil {
				return err
			}
		}

		if !seed {

			for uid, delta := range userDeltas {
				if delta <= 0 {
					continue
				}
				if gen, ok := skipUsers[uid]; ok && s.Runtime.resetSkipValid(uid, gen) {
					continue
				}
				if fence.resetChanged[uid] {
					continue
				}
				q := tx.Model(&model.User{}).Where("id = ?", uid)
				if fence.resetGens != nil {
					if gen, ok := fence.resetGens[uid]; ok {
						q = q.Where("traffic_reset_gen = ?", gen)
					}
				}
				res := q.Update("traffic_used", gorm.Expr("traffic_used + ?", delta))
				if res.Error != nil {
					return res.Error
				}
				if res.RowsAffected == 0 {
					missedReset[uid] = true
				}
			}

			for id, d := range tunnelDeltas {
				if d.in == 0 && d.out == 0 {
					continue
				}
				uid, ok := tunnelOwner[id]
				if !ok {
					continue
				}
				row := model.TrafficDaily{
					UserID:   uid,
					TunnelID: id,
					Date:     today,
					InBytes:  d.in,
					OutBytes: d.out,
				}
				if err := tx.Clauses(clause.OnConflict{
					Columns: []clause.Column{{Name: "user_id"}, {Name: "tunnel_id"}, {Name: "date"}},
					DoUpdates: clause.Assignments(map[string]any{
						"in_bytes":  gorm.Expr("lt_traffic_daily.in_bytes + ?", d.in),
						"out_bytes": gorm.Expr("lt_traffic_daily.out_bytes + ?", d.out),
					}),
				}).Create(&row).Error; err != nil {
					return err
				}
			}
		}

		if !seed {
			for uid := range fence.resetChanged {
				missedReset[uid] = true
			}
		}
		for uid := range missedReset {
			var cur int64
			if err := tx.Model(&model.User{}).Where("id = ?", uid).
				Pluck("traffic_reset_gen", &cur).Error; err != nil {
				return err
			}
			committedGens[uid] = cur
		}
		if len(committedGens) > 0 {
			marks := make([]model.TrafficResetMark, 0, len(committedGens))
			for uid, gen := range committedGens {
				marks = append(marks, model.TrafficResetMark{UserID: uid, Gen: gen})
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"gen", "updated_at"}),
			}).Create(&marks).Error; err != nil {
				return err
			}
		}

		if err := tx.Where("date <> ?", today).Delete(&model.TrafficBaseline{}).Error; err != nil {
			return err
		}

		names := make([]string, 0, len(nextStat))
		for name, cur := range nextStat {
			names = append(names, name)
			row := model.TrafficBaseline{
				ProxyName: name,
				Date:      today,
				InBytes:   cur.in,
				OutBytes:  cur.out,
				TunnelID:  cur.tunnelID,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "proxy_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"date", "in_bytes", "out_bytes", "tunnel_id"}),
			}).Create(&row).Error; err != nil {
				return err
			}
		}
		if len(names) == 0 {
			if err := tx.Where("1 = 1").Delete(&model.TrafficBaseline{}).Error; err != nil {
				return err
			}
		} else if err := tx.Where("proxy_name NOT IN ?", names).
			Delete(&model.TrafficBaseline{}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.Runtime.consumePendingTrafficResets(skipUsers)
	s.Runtime.rememberResetGens(committedGens)
	return nil
}
