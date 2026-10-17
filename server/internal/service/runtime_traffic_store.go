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

// leaseTrafficCollector 是「流量采集」的跨实例租约名。
const leaseTrafficCollector = "traffic-collector"

// trafficCollectLease 是采集租约的时长：必须长于一轮采集（含 frps 往返），
// 否则正常采集中的实例会被另一个实例抢走，两边同时记账。
const trafficCollectLease = 2 * time.Minute

// acquireLease 抢占（或续租）一个跨实例租约，返回本次的代次与是否持有。
//
// 抢占用条件更新：只有把 expires_at 推进成功的那一个实例，在租期内独占。
// 首次插入即成功；已存在时按「已过期」或「仍由我持有」续租——后者让持有者
// 每轮都能刷新租期，而不必等它过期。每次成功都推进 Gen（fencing token），
// 写库时在事务内核对它，过期持有者的写入会被拒。
//
// 插入失败不能一律当成「已被占用」：也可能是数据库真出错。此时走更新分支，
// 失败就返回 false（这一轮不采集），错误会在下一轮重试。
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
	// 只有持有者能推进代次，所以这里读回的必然是自己刚写入的那个值。
	var lease model.RuntimeLease
	if err := s.DB.Where("name = ?", name).First(&lease).Error; err != nil {
		log.Printf("[lease] 读取租约 %s 代次失败: %v", name, err)
		return 0, false
	}
	return lease.Gen, true
}

// releaseLease 主动交还租约（仅当持有者是自己）。
//
// 正常退出时调用：新进程不必等租期到期就能接手采集。
// 崩溃退出时没人调用，租约自然过期——所以租期本身要短于「可接受的空窗」。
//
// 交还时也推进代次：任何仍拿着旧代次的在途写库都会因此被拒，
// 不会出现「已经交还了、旧进程又写进一笔」。
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

// flushTraffic 将本轮增量与采样基线一并写库。
//
// 返回错误而不是只记日志：调用方要靠它决定**要不要推进内存里的采样基线**。
// 失败时推进基线等于把这一轮的流量永久丢掉。
//
// nextStat 是本轮采样到的新基线，必须与增量在同一个事务里提交：
//
//   - 增量记上了、基线没推进 → 下一轮会把同一批流量再算一遍（重复计入）；
//   - 基线推进了、增量没记上 → 这批流量永久漏记。
//
// 两种失真都会直接影响用户配额，且事后很难发现，所以它们必须同生共死。
//
// seed 为 true 时只写基线、跳过全部增量写入：这是基线表首次迁移后的
// 第一轮采集，frps 的当天累计值是旧版本已经计过的，从零起算会把当天
// 已计流量整个重复计入（见 loadTrafficBaseline 的迁移标记说明）。
// errLeaseLost 表示落库时发现采集租约已被别的实例接手。
var errLeaseLost = errors.New("采集租约已被其他实例接手")

// trafficFence 是落库时的写库闸门。
//
// 零值表示「不参与校验」——只有测试会直接调用 flushTraffic；
// 生产路径一定带上租约代次与清零代次。
type trafficFence struct {
	// leaseGen 是本次采集持有的租约代次，0 表示不校验租约。
	leaseGen int64
	// resetGens 是采样时刻各用户的清零代次；resetChanged 是「自上次提交以来
	// 代次变过」的用户集合（清零可能来自别的实例，本地标记看不见）。
	resetGens    map[uint]int64
	resetChanged map[uint]bool
}

func (s *Services) flushTraffic(
	tunnelDeltas map[uint]*tunnelDelta,
	userDeltas map[uint]int64,
	tunnelOwner map[uint]uint,
	nextStat map[string]trafficPair,
	seed bool,
	// fence 是本轮采集的写库闸门；零值表示调用方不参与（测试直接调用）。
	fence trafficFence,
) error {
	now := time.Now()
	today := now.Format("2006-01-02")

	// 整轮（快照 → 事务校验 → 提交 → 摘除）持清零协调锁：撤销只能发生在
	// 本轮之前或之后，不会插进「代次校验通过」与「事务提交」之间——
	// 否则清零写库失败并撤销后，这一轮仍会按已失效的标记跳过真实增量。
	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

	// 在事务**外**对清零标记做快照：快照只读不摘，事务失败时标记原样
	// 留在 map 里等下一轮；事务成功后按代次摘除已消费的标记。
	// （旧实现是「取走即消费、失败再归还」，但归还拦不住登记方紧随其后的
	// 撤销——一次失败的清零仍会让采集器丢一轮真实用量。）
	skipUsers := s.Runtime.takePendingTrafficResets()

	// missedReset 记录「条件更新没命中」的用户：事务期间发生过清零。
	missedReset := make(map[uint]bool)
	// committedGens 是本次基线推进后应当记下的清零代次（落库 + 内存各一份）。
	committedGens := make(map[uint]int64, len(fence.resetGens))
	for uid, gen := range fence.resetGens {
		committedGens[uid] = gen
	}

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// fencing：在同一事务里锁住租约行并核对代次。
		//
		// 只在事务外「续租成功才写」是不够的：进程暂停或事务排队时租约仍可能
		// 在检查与提交之间被接手，两边于是各提交一份同一段增量。锁住这一行之后，
		// 接手的实例必须等本事务结束才能改它，而本事务在改之前就核对过代次。
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

		// 在线时间**不受 seed 影响**：它记的是「这条隧道此刻在线」，
		// 与流量计费无关。seed 轮跳过的是增量（避免把当天累计重复计入），
		// 但用户接口靠 last_online_at 判断在线——首轮不写的话，迁移后的
		// 第一轮里所有隧道都会显示离线。
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

			// 管理员清零与采集增量的协调（见 pendingTrafficReset）：
			// 清零后紧邻一轮的增量是清零前采样的旧流量，加回去等于
			// 「清零完又冒出来」。标记已在事务外做快照（skipUsers），
			// 这里按**仍然有效**的跳过——清零时刻之前的增量全部丢弃。
			// 登记方撤销（清零写库失败）后快照即刻失效，真实用量照常入账。
			// 隧道级统计照常累加：清零的是用户的周期用量，
			// 隧道的累计与日明细不受影响。
			for uid, delta := range userDeltas {
				if delta <= 0 {
					continue
				}
				if gen, ok := skipUsers[uid]; ok && s.Runtime.resetSkipValid(uid, gen) {
					continue
				}
				// 自上次提交以来被清零过（可能来自别的实例）：这一轮增量横跨了
				// 清零点，丢弃。库里的条件更新只能挡住「事务期间」的清零，
				// 挡不住「上一轮之后」的清零。
				if fence.resetChanged[uid] {
					continue
				}
				q := tx.Model(&model.User{}).Where("id = ?", uid)
				// 跨实例的清零协调：只在「清零代次仍等于本轮采样时读到的值」
				// 时累加。代次对不上说明期间发生过清零（可能来自别的实例），
				// 这笔增量属于清零前的流量，丢掉才对。
				if fence.resetGens != nil {
					if gen, ok := fence.resetGens[uid]; ok {
						q = q.Where("traffic_reset_gen = ?", gen)
					}
				}
				res := q.Update("traffic_used", gorm.Expr("traffic_used + ?", delta))
				if res.Error != nil {
					return res.Error
				}
				// RowsAffected = 0：期间被清零，这笔增量不计。
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
				// 唯一键 (user_id, tunnel_id, date) 上做累加 upsert。
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

		// 期间被清零的用户（本地快照判定「变过」或条件更新没命中）：
		// 把库里**当前**的代次记为「本轮基线对应的代次」。
		// 记旧值的话，下一轮还会再判一次「变过」，白丢一轮清零后的真实流量。
		//
		// 播种轮（seed）跳过这一步：本轮只写基线、不计增量，此时把「代次
		// 未知」的哨兵改写成当前值，等于宣告「这份基线对应的就是当前代次」，
		// 而它恰恰可能是升级前那份——正好丢掉这条迁移要保住的信息。
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
		// 代次与基线一起落库：重启/换手后据此判断「期间有没有被清零过」。
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

		// ---- 采样基线 ----
		//
		// 昨天的基线直接删掉：frps 的当日累计值跨零点归零，拿昨天的基线
		// 相减会得到负数（调用方会把负数当「当天全部流量」处理，等于把
		// 新一天的流量重复算一遍）。
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
				// 记下隧道行 ID：同名隧道删了重建时，靠它认出「这不是原来那条代理」。
				TunnelID: cur.tunnelID,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "proxy_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"date", "in_bytes", "out_bytes", "tunnel_id"}),
			}).Create(&row).Error; err != nil {
				return err
			}
		}
		// 已经消失的代理要把基线删掉，否则这张表会随历史代理一直长。
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
		// 事务失败（含提交失败）：基线还停在旧值，标记原样留在 map 里，
		// 下一轮继续按它跳过——「清零完又冒出来」正是要防的。
		return err
	}
	// 成功提交：本轮快照消费完毕。期间被重新登记的用户代次已推进，
	// consume 只摘除代次未变的，新标记留给下一轮。
	s.Runtime.consumePendingTrafficResets(skipUsers)
	// 记下本轮提交时的清零代次（含期间被清零、已改成当前值的用户），
	// 供下一轮判断「期间是否被清零过」。
	s.Runtime.rememberResetGens(committedGens)
	return nil
}
