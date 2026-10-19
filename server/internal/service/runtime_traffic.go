package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const baselineLegacyKeep = time.Hour

func (s *Services) pruneDeadBaselines(nextStat map[string]trafficPair, seen map[string]bool, now time.Time) {
	ids := make([]uint, 0, len(nextStat))
	for name, prev := range nextStat {
		if seen[name] || prev.tunnelID == 0 {
			continue
		}
		ids = append(ids, prev.tunnelID)
	}

	alive := make(map[uint]bool, len(ids))
	if len(ids) > 0 {
		for start := 0; start < len(ids); start += inQueryBatch {
			end := start + inQueryBatch
			if end > len(ids) {
				end = len(ids)
			}
			var batch []uint
			if err := s.DB.Model(&model.Tunnel{}).
				Where("id IN ?", ids[start:end]).Pluck("id", &batch).Error; err != nil {
				for _, id := range ids[start:end] {
					alive[id] = true
				}
				continue
			}
			for _, id := range batch {
				alive[id] = true
			}
		}
	}

	for name, prev := range nextStat {
		if seen[name] {
			continue
		}
		if prev.tunnelID == 0 {
			if now.Sub(prev.seenAt) > baselineLegacyKeep {
				delete(nextStat, name)
			}
			continue
		}
		if !alive[prev.tunnelID] {
			delete(nextStat, name)
		}
	}
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

type trafficPair struct {
	in       int64
	out      int64
	tunnelID uint
	unknown  bool
	seenAt   time.Time
}

type tunnelDelta struct {
	in     int64
	out    int64
	online bool
}

func (s *Services) StartTrafficCollector(ctx context.Context) <-chan struct{} {
	interval := s.Cfg.TrafficPollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer s.releaseLease(leaseTrafficCollector)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		gcTicker := time.NewTicker(10 * time.Minute)
		defer gcTicker.Stop()

		guardReady := s.LoadAccessGuard()

		baselineReady := s.loadTrafficBaseline()
		if baselineReady {
			s.collectTraffic(ctx)
		} else {
			log.Printf("[traffic] 采样基线尚未就绪，本轮跳过采集（下个周期重试）")
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.ReloadSettingsIfChanged()
				s.refreshGuardDue()
				if !guardReady {
					if guardReady = s.LoadAccessGuard(); guardReady {
						log.Printf("[quota] 准入状态已就绪，恢复按配额与账号状态拦截")
					}
				}
				if !baselineReady {
					if baselineReady = s.loadTrafficBaseline(); !baselineReady {
						continue
					}
					log.Printf("[traffic] 采样基线已恢复，继续采集")
				}
				s.collectTraffic(ctx)
			case <-gcTicker.C:
				s.Runtime.GC(15 * time.Minute)
				s.MarkStaleSessionsOffline(5 * time.Minute)
			}
		}
	}()
	return done
}

var inQueryBatch = 500

func queryInBatches[T any](db *gorm.DB, column string, ids []uint) ([]T, error) {
	var out []T
	for start := 0; start < len(ids); start += inQueryBatch {
		end := start + inQueryBatch
		if end > len(ids) {
			end = len(ids)
		}
		var batch []T
		if err := db.Where(column+" IN ?", ids[start:end]).Find(&batch).Error; err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

func (s *Services) collectTraffic(ctx context.Context) {
	if _, ok := s.acquireLease(leaseTrafficCollector, trafficCollectLease); !ok {
		if s.collectorOwned.Swap(false) {
			log.Printf("[traffic] 采集租约已转交其他实例，本实例暂停采集")
		}
		return
	}
	if !s.collectorOwned.Load() {
		if !s.loadTrafficBaseline() {
			s.releaseLease(leaseTrafficCollector)
			s.collectorOwned.Store(false)
			log.Printf("[traffic] 取得采集租约时读取基线失败，已交还租约（下轮重试）")
			return
		}
		s.collectorOwned.Store(true)
		log.Printf("[traffic] 已取得采集租约，按库中基线继续采集")
	}

	proxies, err := s.Frps.ListProxies(ctx)
	if err != nil {
		log.Printf("[traffic] 拉取 frps 代理状态失败（保留上次在线状态）: %v", err)
		return
	}

	type proxyRef struct {
		idx        int
		userID     uint
		tunnelName string
	}
	refs := make([]proxyRef, 0, len(proxies))
	userIDs := make([]uint, 0, len(proxies))
	seenUser := make(map[uint]bool, len(proxies))
	for i, p := range proxies {
		frpUser, tunnelName, ok := ParseProxyName(p.Name)
		if !ok {
			continue
		}
		userID, ok := UserIDFromFrpUser(frpUser)
		if !ok {
			continue
		}
		refs = append(refs, proxyRef{idx: i, userID: userID, tunnelName: tunnelName})
		if !seenUser[userID] {
			seenUser[userID] = true
			userIDs = append(userIDs, userID)
		}
	}

	type tunnelKey struct {
		userID uint
		tunnel string
	}
	userByID := make(map[uint]*model.User, len(userIDs))
	tunnelByKey := make(map[tunnelKey]*model.Tunnel, len(refs))
	tunnelOwner := make(map[uint]uint, len(refs))
	var resetGens map[uint]int64
	if len(userIDs) > 0 {
		users, err := queryInBatches[model.User](s.DB, "id", userIDs)
		if err != nil {
			log.Printf("[traffic] 载入用户失败: %v", err)
			return
		}
		for i := range users {
			userByID[users[i].ID] = &users[i]
		}
		resetGens = make(map[uint]int64, len(users))
		for i := range users {
			resetGens[users[i].ID] = users[i].TrafficResetGen
		}

		tunnels, err := queryInBatches[model.Tunnel](s.DB, "user_id", userIDs)
		if err != nil {
			log.Printf("[traffic] 载入隧道失败: %v", err)
			return
		}
		for i := range tunnels {
			tunnelByKey[tunnelKey{userID: tunnels[i].UserID, tunnel: tunnels[i].Name}] = &tunnels[i]
			tunnelOwner[tunnels[i].ID] = tunnels[i].UserID
		}
	}

	tunnelDeltas := make(map[uint]*tunnelDelta, len(refs))
	userDeltas := make(map[uint]int64, len(userIDs))
	onlineNow := make(map[uint]bool, len(refs))

	s.Runtime.mu.Lock()
	lastStat := s.Runtime.lastStat
	now := time.Now()
	nextStat := make(map[string]trafficPair, len(proxies))
	for name, prev := range lastStat {
		if sameDay(prev.seenAt, now) {
			nextStat[name] = prev
		}
	}
	seenNames := make(map[string]bool, len(refs))

	for _, ref := range refs {
		p := proxies[ref.idx]
		u, ok := userByID[ref.userID]
		if !ok {
			continue
		}
		t, ok := tunnelByKey[tunnelKey{userID: ref.userID, tunnel: ref.tunnelName}]
		if !ok {
			continue
		}

		cur := trafficPair{in: p.Status.TodayTrafficIn, out: p.Status.TodayTrafficOut,
			seenAt: now, tunnelID: t.ID}
		prev := lastStat[p.Name]
		if prev.tunnelID != 0 && prev.tunnelID != t.ID {
			prev = trafficPair{}
		}
		din, dout := cur.in-prev.in, cur.out-prev.out
		if prev.unknown {
			din, dout = 0, 0
		}
		if din < 0 {
			din = cur.in
		}
		if dout < 0 {
			dout = cur.out
		}
		nextStat[p.Name] = cur
		seenNames[p.Name] = true

		d := tunnelDeltas[t.ID]
		if d == nil {
			d = &tunnelDelta{}
			tunnelDeltas[t.ID] = d
		}
		d.in += din
		d.out += dout
		running := IsProxyOnline(p.Status.Phase)
		d.online = d.online || running
		if running {
			onlineNow[t.ID] = true
		}
		userDeltas[u.ID] += din + dout
	}
	s.Runtime.mu.Unlock()

	s.Runtime.setOnlineTunnels(onlineNow)

	s.pruneDeadBaselines(nextStat, seenNames, now)

	s.Runtime.mu.Lock()
	seedBaseline := s.Runtime.baselineSeedPending
	s.Runtime.mu.Unlock()

	renewGen, ok := s.acquireLease(leaseTrafficCollector, trafficCollectLease)
	if !ok {
		s.collectorOwned.Store(false)
		log.Printf("[traffic] 采集租约已被其他实例接手，本轮结果丢弃（不写账）")
		return
	}
	changed := s.Runtime.changedResetGens(resetGens)

	fence := trafficFence{
		leaseGen:     renewGen,
		resetGens:    resetGens,
		resetChanged: changed,
	}

	if err := s.flushTraffic(tunnelDeltas, userDeltas, tunnelOwner, nextStat, seedBaseline, fence); err != nil {
		if errors.Is(err, errLeaseLost) {
			s.collectorOwned.Store(false)
			log.Printf("[traffic] 租约在落库前被接管，本轮结果丢弃（不写账）")
			return
		}
		log.Printf("[traffic] 流量落库失败，本轮不推进采样基线（增量下轮补记）: %v", err)
	} else {
		s.Runtime.mu.Lock()
		s.Runtime.lastStat = nextStat
		seedReset := s.Runtime.resetMarkSeedPending
		s.Runtime.baselineSeedPending = false
		s.Runtime.resetMarkSeedPending = false
		s.Runtime.mu.Unlock()
		if seedBaseline {
			if err := s.Settings.SetInternal(map[SettingKey]string{KeyTrafficBaselineReady: "1"}); err != nil {
				log.Printf("[traffic] 写入基线迁移标记失败（下轮仍按首次迁移处理）: %v", err)
			} else {
				log.Printf("[traffic] 首次基线已建立，后续采集恢复正常计增量")
			}
		}
		if seedReset {
			if err := s.Settings.SetInternal(map[SettingKey]string{KeyTrafficResetMarkReady: "1"}); err != nil {
				log.Printf("[traffic] 写入清零代次迁移标记失败（下轮仍按首次处理）: %v", err)
			} else {
				log.Printf("[traffic] 清零代次标记已初始化，后续采集恢复正常计增量")
			}
		}
	}
	s.refreshGuardForTraffic(userDeltas)
}

func (s *Services) loadTrafficBaseline() bool {
	seed := !s.Settings.Bool(KeyTrafficBaselineReady)
	seedReset := !s.Settings.Bool(KeyTrafficResetMarkReady)

	today := time.Now().Format("2006-01-02")
	var rows []model.TrafficBaseline
	if err := s.DB.Where("date = ?", today).Find(&rows).Error; err != nil {
		log.Printf("[traffic] 读取采样基线失败，将跳过采集以避免重复计入当天流量: %v", err)
		return false
	}

	now := time.Now()
	m := make(map[string]trafficPair, len(rows))
	for _, r := range rows {
		m[r.ProxyName] = trafficPair{in: r.InBytes, out: r.OutBytes,
			seenAt: now, tunnelID: r.TunnelID, unknown: r.TunnelID == 0}
	}

	var marks []model.TrafficResetMark
	if err := s.DB.Find(&marks).Error; err != nil {
		log.Printf("[traffic] 读取清零代次标记失败，将跳过采集以避免把清零前的流量加回来: %v", err)
		return false
	}
	gens := make(map[uint]int64, len(marks))
	for _, mk := range marks {
		gens[mk.UserID] = mk.Gen
	}
	if seedReset {
		if err := s.seedUnknownResetGens(gens); err != nil {
			log.Printf("[traffic] 清零代次标记初始化失败，本轮跳过采集（下轮重试）: %v", err)
			return false
		}
	}

	s.Runtime.mu.Lock()
	s.Runtime.lastStat = m
	s.Runtime.baselineSeedPending = seed || seedReset
	s.Runtime.resetMarkSeedPending = seedReset
	s.Runtime.lastResetGen = gens
	s.Runtime.mu.Unlock()

	if len(m) > 0 {
		log.Printf("[traffic] 已恢复 %d 条采样基线（避免重启后重复计入当天流量）", len(m))
	}
	if seed {
		log.Printf("[traffic] 未发现基线迁移标记，第一轮采集只记录基线、不计流量增量")
	}
	if seedReset {
		log.Printf("[traffic] 未发现清零代次标记，第一轮采集只记录基线、不计流量增量")
	}
	return true
}

func (s *Services) seedUnknownResetGens(gens map[uint]int64) error {
	var ids []uint
	if err := s.DB.Model(&model.User{}).Pluck("id", &ids).Error; err != nil {
		return fmt.Errorf("读取用户列表失败: %w", err)
	}
	marks := make([]model.TrafficResetMark, 0, len(ids))
	for _, id := range ids {
		if _, ok := gens[id]; ok {
			continue
		}
		gens[id] = resetGenUnknown
		marks = append(marks, model.TrafficResetMark{UserID: id, Gen: resetGenUnknown})
	}
	if len(marks) == 0 {
		return nil
	}
	if err := s.DB.Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(&marks, 200).Error; err != nil {
		return fmt.Errorf("写入清零代次哨兵失败: %w", err)
	}
	log.Printf("[traffic] 已为 %d 个用户写入「清零代次未知」标记，下次采样时保守跳过一轮增量", len(marks))
	return nil
}
