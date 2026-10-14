package service

import (
	"context"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// sessionInfo 一次 frpc 登录会话的缓存，避免插件回调频繁打库。
type sessionInfo struct {
	UserID   uint
	Username string
	LastSeen time.Time
}

type trafficPair struct {
	in  int64
	out int64
}

// tunnelDelta 单轮采集内某条隧道的流量增量与在线态。
type tunnelDelta struct {
	in     int64
	out    int64
	online bool
}

// Runtime 保存插件回调与流量采集共用的内存态。
//
// 之所以放在内存：frps 的 NewUserConn 回调在每次新建用户连接时都会触发，
// 这条高频路径上不允许出现数据库查询。
type Runtime struct {
	mu sync.RWMutex

	sessions map[string]sessionInfo // runID -> 会话
	exceeded map[uint]bool          // userID -> 是否超额
	online   map[uint]bool          // tunnelID -> 是否在线
	lastStat map[string]trafficPair // frp 代理全名 -> 上次采样的当日累计值
	touchAt  map[string]time.Time   // runID -> 上次会话落库时间（节流用）
}

// NewRuntime 构造内存态。
func NewRuntime() *Runtime {
	return &Runtime{
		sessions: make(map[string]sessionInfo),
		exceeded: make(map[uint]bool),
		online:   make(map[uint]bool),
		lastStat: make(map[string]trafficPair),
		touchAt:  make(map[string]time.Time),
	}
}

// ShouldTouch 判断某会话是否已达到落库节流间隔。
// frpc 的心跳默认 30 秒一次，若每次都写库会造成无谓的写放大。
func (r *Runtime) ShouldTouch(runID string, interval time.Duration) bool {
	if runID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.touchAt[runID]
	if ok && time.Since(last) < interval {
		return false
	}
	r.touchAt[runID] = time.Now()
	return true
}

// TouchClientSession 以节流方式刷新客户端会话的在线时间。
func (s *Services) TouchClientSession(runID string) {
	if !s.Runtime.ShouldTouch(runID, time.Minute) {
		return
	}
	_ = s.DB.Model(&model.ClientSession{}).Where("run_id = ?", runID).
		Updates(map[string]any{"online": true, "last_seen_at": time.Now()}).Error
}

// MarkStaleSessionsOffline 把长时间未上报心跳的会话标记为离线。
func (s *Services) MarkStaleSessionsOffline(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	_ = s.DB.Model(&model.ClientSession{}).
		Where("online = ? AND last_seen_at < ?", true, cutoff).
		Update("online", false).Error
}

// RecordLogin 记录一次成功登录。
func (r *Runtime) RecordLogin(runID string, userID uint, username string) {
	if runID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[runID] = sessionInfo{UserID: userID, Username: username, LastSeen: time.Now()}
}

// LookupSession 按 runID 查会话。
func (r *Runtime) LookupSession(runID string) (sessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[runID]
	return s, ok
}

// TouchSession 刷新会话活跃时间。
func (r *Runtime) TouchSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[runID]; ok {
		s.LastSeen = time.Now()
		r.sessions[runID] = s
	}
}

// DropSession 注销会话。
func (r *Runtime) DropSession(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, runID)
}

// IsQuotaExceeded 查询用户是否超额。
func (r *Runtime) IsQuotaExceeded(userID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.exceeded[userID]
}

// SetQuotaExceeded 写入超额状态。
func (r *Runtime) SetQuotaExceeded(userID uint, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v {
		r.exceeded[userID] = true
	} else {
		delete(r.exceeded, userID)
	}
}

// IsTunnelOnline 查询隧道在线态。
func (r *Runtime) IsTunnelOnline(tunnelID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.online[tunnelID]
}

func (r *Runtime) setOnlineTunnels(m map[uint]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.online = m
}

// GC 清理长时间无心跳的会话。
func (r *Runtime) GC(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.sessions {
		if v.LastSeen.Before(cutoff) {
			delete(r.sessions, k)
		}
	}
}

// StartTrafficCollector 启动后台采集协程，直到 ctx 结束。
func (s *Services) StartTrafficCollector(ctx context.Context) {
	interval := s.Cfg.TrafficPollInterval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		gcTicker := time.NewTicker(10 * time.Minute)
		defer gcTicker.Stop()

		// 启动即跑一次，避免控制台首屏空白。
		s.collectTraffic(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.collectTraffic(ctx)
			case <-gcTicker.C:
				s.Runtime.GC(15 * time.Minute)
				s.MarkStaleSessionsOffline(5 * time.Minute)
			}
		}
	}()
}

// collectTraffic 单次采集：拉取 frps 代理状态，计算增量并落库。
func (s *Services) collectTraffic(ctx context.Context) {
	proxies, err := s.Frps.ListProxies(ctx)
	if err != nil {
		// 采集失败不致命：frps 可能正在重启，下一轮会自动恢复。
		log.Printf("[traffic] 拉取 frps 代理状态失败: %v", err)
		return
	}

	// 一次性载入映射表。单机部署下规模有限，用内存换掉 N+1 查询。
	var users []model.User
	if err := s.DB.Find(&users).Error; err != nil {
		log.Printf("[traffic] 载入用户失败: %v", err)
		return
	}
	userByName := make(map[string]*model.User, len(users))
	userNameByID := make(map[uint]string, len(users))
	for i := range users {
		userByName[users[i].Username] = &users[i]
		userNameByID[users[i].ID] = users[i].Username
	}

	var tunnels []model.Tunnel
	if err := s.DB.Find(&tunnels).Error; err != nil {
		log.Printf("[traffic] 载入隧道失败: %v", err)
		return
	}
	type tunnelKey struct{ username, tunnel string }
	tunnelByKey := make(map[tunnelKey]*model.Tunnel, len(tunnels))
	tunnelOwner := make(map[uint]uint, len(tunnels))
	for i := range tunnels {
		uname := userNameByID[tunnels[i].UserID]
		if uname == "" {
			continue
		}
		tunnelByKey[tunnelKey{username: uname, tunnel: tunnels[i].Name}] = &tunnels[i]
		tunnelOwner[tunnels[i].ID] = tunnels[i].UserID
	}

	tunnelDeltas := make(map[uint]*tunnelDelta, len(tunnels))
	userDeltas := make(map[uint]int64)
	onlineNow := make(map[uint]bool, len(tunnels))
	seen := make(map[string]struct{}, len(proxies))

	s.Runtime.mu.Lock()
	lastStat := s.Runtime.lastStat
	for _, p := range proxies {
		frpUser, tunnelName, ok := ParseProxyName(p.Name)
		if !ok {
			continue
		}
		username, ok := UsernameFromFrpUser(frpUser)
		if !ok {
			continue
		}
		u, ok := userByName[username]
		if !ok {
			continue
		}
		t, ok := tunnelByKey[tunnelKey{username: username, tunnel: tunnelName}]
		if !ok {
			continue
		}

		seen[p.Name] = struct{}{}
		cur := trafficPair{in: p.Status.TodayTrafficIn, out: p.Status.TodayTrafficOut}
		prev := lastStat[p.Name]
		din, dout := cur.in-prev.in, cur.out-prev.out
		// frps 的当日统计跨零点归零，此时当前值本身就是增量。
		if din < 0 {
			din = cur.in
		}
		if dout < 0 {
			dout = cur.out
		}
		lastStat[p.Name] = cur

		d := tunnelDeltas[t.ID]
		if d == nil {
			d = &tunnelDelta{}
			tunnelDeltas[t.ID] = d
		}
		d.in += din
		d.out += dout
		running := p.Status.Phase == "running"
		d.online = d.online || running
		if running {
			onlineNow[t.ID] = true
		}
		userDeltas[u.ID] += din + dout
	}
	// 清理已消失的代理采样，防止内存随历史代理无限增长。
	for name := range lastStat {
		if _, ok := seen[name]; !ok {
			delete(lastStat, name)
		}
	}
	s.Runtime.mu.Unlock()

	s.Runtime.setOnlineTunnels(onlineNow)
	s.flushTraffic(tunnelDeltas, userDeltas, tunnelOwner)
	s.refreshQuotaFlags()
}

// flushTraffic 将本轮增量写库。
func (s *Services) flushTraffic(tunnelDeltas map[uint]*tunnelDelta, userDeltas map[uint]int64, tunnelOwner map[uint]uint) {
	now := time.Now()
	today := now.Format("2006-01-02")

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		for id, d := range tunnelDeltas {
			total := d.in + d.out
			if total == 0 && !d.online {
				continue
			}
			updates := map[string]any{}
			if total > 0 {
				updates["traffic_used"] = gorm.Expr("traffic_used + ?", total)
			}
			if d.online {
				updates["last_online_at"] = now
			}
			if len(updates) == 0 {
				continue
			}
			if err := tx.Model(&model.Tunnel{}).Where("id = ?", id).Updates(updates).Error; err != nil {
				return err
			}
		}

		for uid, delta := range userDeltas {
			if delta <= 0 {
				continue
			}
			if err := tx.Model(&model.User{}).Where("id = ?", uid).
				Update("traffic_used", gorm.Expr("traffic_used + ?", delta)).Error; err != nil {
				return err
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
		return nil
	})
	if err != nil {
		log.Printf("[traffic] 流量落库失败: %v", err)
	}
}

// refreshQuotaFlags 刷新内存中的超额标记，供 frps 插件实时拦截。
func (s *Services) refreshQuotaFlags() {
	var users []model.User
	if err := s.DB.Preload("Group").Find(&users).Error; err != nil {
		log.Printf("[quota] 刷新超额标记失败: %v", err)
		return
	}
	for i := range users {
		s.EnsureTrafficPeriod(&users[i])
		s.Runtime.SetQuotaExceeded(users[i].ID, s.QuotaExceeded(&users[i]))
	}
}
