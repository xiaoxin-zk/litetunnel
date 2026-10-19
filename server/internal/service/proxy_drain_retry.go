package service

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	proxyDrainRetryInterval = 30 * time.Second
	proxyDrainBaseDelay     = 30 * time.Second
	proxyDrainMaxDelay      = 30 * time.Minute
	proxyDrainMaxAttempts   = 10
	proxyDrainLease         = closeProxiesTimeout + 30*time.Second
	proxyDrainBatchSize     = 8
)

func proxyDrainRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := proxyDrainBaseDelay
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= proxyDrainMaxDelay {
			return proxyDrainMaxDelay
		}
	}
	return d
}

func proxyDrainSuspectsJSON(names []string) string {
	if len(names) == 0 {
		return ""
	}
	raw, err := json.Marshal(names)
	if err != nil {
		return strings.Join(names, ", ")
	}
	return string(raw)
}

func decodeProxyDrainSuspects(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func proxyDrainTargetsJSON(targets []proxyDrainTarget) string {
	if len(targets) == 0 {
		return ""
	}
	raw, err := json.Marshal(targets)
	if err != nil {
		log.Printf("[proxy-drain] 实例身份快照序列化失败（退化为按时间水位判断）: %v", err)
		return ""
	}
	return string(raw)
}

func decodeProxyDrainTargets(raw string) []proxyDrainTarget {
	if raw == "" {
		return nil
	}
	var out []proxyDrainTarget
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Printf("[proxy-drain] 待办里的实例身份快照无法解析，按空快照处理: %v", err)
		return nil
	}
	return out
}

func (s *Services) recordProxyDrainPending(req proxyDrainRequest) string {
	return s.recordProxyDrainPendingDB(s.DB, req)
}

func (s *Services) recordProxyDrainPendingDB(db *gorm.DB, req proxyDrainRequest) string {
	if db == nil {
		return ""
	}
	fence, err := randomHex(16)
	if err != nil {
		log.Printf("[proxy-drain] 生成待办围栏令牌失败（用户 %d）: %v", req.userID, err)
		return ""
	}
	incarnation := req.incarnation
	if incarnation == "" {
		var u model.User
		if err := db.Select("id", "incarnation").First(&u, req.userID).Error; err != nil {
			log.Printf("[proxy-drain] 读取用户 %d 的账号标识失败（待办仍会登记，重试时按不可核验处理）: %v",
				req.userID, err)
		} else {
			incarnation = u.Incarnation
		}
	}
	rec := model.ProxyDrainPending{
		UserID:      req.userID,
		Incarnation: incarnation,
		Prefix:      req.prefix,
		StatusGen:   req.gen,
		NotAfter:    unixOrZero(req.notAfter),
		Deleted:     req.deleted,
		IntentAt:    time.Now().Unix(),
		Targets:     proxyDrainTargetsJSON(req.known),
		Attempts:    0,
		NextAt:      time.Now().Add(proxyDrainBaseDelay),
		Fence:       fence,
	}
	res := db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"incarnation": gorm.Expr(`CASE WHEN excluded.incarnation <> ''
				THEN excluded.incarnation ELSE lt_proxy_drain_pending.incarnation END`),
			"prefix":        gorm.Expr("excluded.prefix"),
			"status_gen":    gorm.Expr("excluded.status_gen"),
			"not_after":     gorm.Expr("excluded.not_after"),
			"deleted":       gorm.Expr("excluded.deleted"),
			"intent_at":     gorm.Expr("excluded.intent_at"),
			"targets":       gorm.Expr("excluded.targets"),
			"attempts":      gorm.Expr("excluded.attempts"),
			"exhausted":     gorm.Expr("excluded.exhausted"),
			"manual_review": false,
			"suspects":      "",
			"next_at":       gorm.Expr("excluded.next_at"),
			"fence":         gorm.Expr("excluded.fence"),
			"last_err":      gorm.Expr("excluded.last_err"),
			"updated_at":    time.Now(),
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr(`(excluded.deleted AND NOT lt_proxy_drain_pending.deleted)
				OR (excluded.deleted = lt_proxy_drain_pending.deleted
				    AND (excluded.status_gen > lt_proxy_drain_pending.status_gen
				         OR (excluded.status_gen = lt_proxy_drain_pending.status_gen
				             AND excluded.intent_at >= lt_proxy_drain_pending.intent_at)))`),
		}},
	}).Create(&rec)
	if res.Error != nil {
		log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败（本次若也没关干净，重启后将没有补偿机会）: %v",
			req.userID, res.Error)
		return ""
	}
	var mine int64
	if err := db.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ?", req.userID, fence).Count(&mine).Error; err != nil {
		log.Printf("[proxy-drain] 读回用户 %d 的断流待办失败: %v", req.userID, err)
		return ""
	}
	if mine == 0 {
		return ""
	}
	return fence
}

func (s *Services) clearProxyDrainPending(userID uint, fence string) {
	if fence == "" || s.DB == nil {
		return
	}
	if err := s.DB.Where("user_id = ? AND fence = ?", userID, fence).
		Delete(&model.ProxyDrainPending{}).Error; err != nil {
		log.Printf("[proxy-drain] 清除用户 %d 的断流待办失败（下轮会把空转再跑一遍，不影响正确性）: %v",
			userID, err)
	}
}

func (s *Services) captureDrainIncarnation(req proxyDrainRequest) proxyDrainRequest {
	if req.incarnation != "" || s.DB == nil {
		return req
	}
	if inc, _, err := s.currentIncarnation(req.userID); err != nil {
		log.Printf("[proxy-drain] 读取用户 %d 的账号标识失败，补偿队列将以空标识登记（重试时会转人工）: %v",
			req.userID, err)
		return req
	} else {
		req.incarnation = inc
	}
	return req
}

func (s *Services) rescheduleProxyDrain(req proxyDrainRequest, out proxyDrainOutcome) {
	if req.noRegister {
		log.Printf("[proxy-drain][ALERT] 用户 %d 的断流没有可依据的待办（noRegister），残留 %d 个代理不做持久化补偿，"+
			"也不会进入补偿队列：请人工核对 frps 中 %s* 下的代理",
			req.userID, len(out.residual), FrpUserOf(req.userID)+".")
		return
	}
	if s.DB == nil {
		return
	}
	if req.intent == "" {
		if s.drainFallback != nil {
			s.drainFallback.enqueue(s.captureDrainIncarnation(req))
			log.Printf("[proxy-drain] 用户 %d 仍有 %d 个代理未能关闭，本次意图未落库，已放入进程内补偿队列",
				req.userID, len(out.residual))
		} else {
			log.Printf("[proxy-drain] 用户 %d 仍有 %d 个代理未能关闭，但本次意图没有落库且无补偿队列（数据库故障），由现有待办的后台重试兜底",
				req.userID, len(out.residual))
		}
		return
	}

	attempts := req.attempts + 1
	delay := proxyDrainRetryDelay(attempts)
	exhausted := attempts >= proxyDrainMaxAttempts

	updates := map[string]any{
		"attempts": attempts,
		"next_at":  time.Now().Add(delay),
		"last_err": truncate(out.lastErr, 255),
	}
	if len(out.suspects) > 0 {
		updates["manual_review"] = true
		updates["exhausted"] = true
		updates["suspects"] = proxyDrainSuspectsJSON(out.suspects)
		updates["last_err"] = truncate(
			"疑似误关：关闭后同名代理以另一实例身份重新出现，已转人工核对（"+strings.Join(out.suspects, ", ")+"）", 255)
	}
	if len(out.residual) > 0 {
		updates["targets"] = proxyDrainTargetsJSON(out.residual)
	}
	if exhausted {
		updates["exhausted"] = true
		updates["next_at"] = time.Now().Add(proxyDrainMaxDelay)
	}

	res := s.DB.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ?", req.userID, req.intent).
		Updates(updates)
	if res.Error != nil {
		log.Printf("[proxy-drain] 更新用户 %d 的断流待办失败（下一轮仍会按旧时间重试）: %v",
			req.userID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		return
	}
	if len(out.suspects) > 0 {
		log.Printf("[proxy-drain][ALERT] 用户 %d 的断流已转为人工待办（停止自动重试，记录已保留）：%s。"+
			"请人工核对 frps 中该前缀下的代理实例，确认后再清理这条待办",
			req.userID, strings.Join(out.suspects, ", "))
	}
	if exhausted {
		log.Printf("[proxy-drain] 用户 %d 的断流连续 %d 次未能完成，已停止自动重试（待办保留：user_id=%d prefix=%s last_err=%s），"+
			"已建立的代理可能仍在转发流量，请人工排查 frps 管理接口或该前缀下的代理",
			req.userID, attempts, req.userID, req.prefix, truncate(out.lastErr, 200))
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeFromUnix(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func requestFromPending(row model.ProxyDrainPending) proxyDrainRequest {
	req := proxyDrainRequest{
		userID:      row.UserID,
		prefix:      row.Prefix,
		gen:         row.StatusGen,
		notAfter:    timeFromUnix(row.NotAfter),
		deleted:     row.Deleted,
		attempts:    row.Attempts,
		intent:      row.Fence,
		known:       decodeProxyDrainTargets(row.Targets),
		incarnation: row.Incarnation,
	}
	if req.prefix == "" {
		req.prefix = FrpUserOf(req.userID) + "."
	}
	if req.deleted && req.notAfter.IsZero() {
		switch {
		case row.IntentAt > 0:
			req.notAfter = timeFromUnix(row.IntentAt)
		case !row.CreatedAt.IsZero():
			req.notAfter = row.CreatedAt
		}
	}
	return req
}

func (s *Services) claimProxyDrain(row *model.ProxyDrainPending, now time.Time) bool {
	fence, err := randomHex(16)
	if err != nil {
		log.Printf("[proxy-drain] 生成领取令牌失败（用户 %d）: %v", row.UserID, err)
		return false
	}
	res := s.DB.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ? AND next_at <= ? AND exhausted = ?",
			row.UserID, row.Fence, now, false).
		Updates(map[string]any{
			"fence":   fence,
			"next_at": now.Add(proxyDrainLease),
		})
	if res.Error != nil {
		log.Printf("[proxy-drain] 领取待办失败（用户 %d）: %v", row.UserID, res.Error)
		return false
	}
	if res.RowsAffected != 1 {
		return false
	}
	row.Fence = fence
	return true
}

type proxyDrainIntent int

const (
	proxyDrainIntentActive proxyDrainIntent = iota
	proxyDrainIntentAbandoned
	proxyDrainIntentUnverifiable
	proxyDrainIntentManual
)

func (s *Services) proxyDrainIntentState(row model.ProxyDrainPending) (proxyDrainIntent, bool) {
	if row.Incarnation == "" {
		_, exists, err := s.currentIncarnation(row.UserID)
		if err != nil {
			log.Printf("[proxy-drain] 用户 %d 的账号标识读取失败，本轮不动手（保留待办继续重试）: %v",
				row.UserID, err)
			return proxyDrainIntentUnverifiable, false
		}
		if exists {
			log.Printf("[proxy-drain] 用户 %d 的待办缺少账号标识且该 ID 上仍有账号，跳过自动断流，转人工确认",
				row.UserID)
			return proxyDrainIntentManual, false
		}
	}
	if row.Deleted {
		_, exists, err := s.currentIncarnation(row.UserID)
		if err != nil {
			log.Printf("[proxy-drain] 已删账号 %d 的账号状态读取失败，本轮不动手（保留待办继续重试）: %v",
				row.UserID, err)
			return proxyDrainIntentUnverifiable, false
		}
		if exists {
			log.Printf("[proxy-drain] 用户 %d 的删号意图登记后该 ID 上重新出现了账号，旧意图作废", row.UserID)
			return proxyDrainIntentAbandoned, false
		}
		return proxyDrainIntentActive, true
	}
	gen, incarnation, err := s.userStateVersionAndIncarnation(row.UserID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return proxyDrainIntentActive, true
	}
	if err != nil {
		log.Printf("[proxy-drain] 用户 %d 的状态版本读取失败，本轮不动手（保留待办继续重试）: %v",
			row.UserID, err)
		return proxyDrainIntentUnverifiable, false
	}
	if row.Incarnation != "" && incarnation != row.Incarnation {
		log.Printf("[proxy-drain] 用户 %d 的账号标识已变化（%s ≠ %s），旧断流意图作废",
			row.UserID, row.Incarnation, incarnation)
		return proxyDrainIntentAbandoned, false
	}
	if gen != row.StatusGen {
		return proxyDrainIntentAbandoned, false
	}
	return proxyDrainIntentActive, false
}

func (s *Services) currentIncarnation(userID uint) (string, bool, error) {
	if s.DB == nil {
		return "", false, errors.New("数据库未初始化")
	}
	var u model.User
	if err := s.DB.Select("id", "incarnation").First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	return u.Incarnation, true, nil
}

func (s *Services) markProxyDrainManual(row model.ProxyDrainPending) {
	if s.DB == nil || row.Fence == "" {
		return
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("user_id = ? AND fence = ?", row.UserID, row.Fence).
		Updates(map[string]any{
			"exhausted": true,
			"last_err":  "缺少账号标识（升级前遗留），已停止自动断流，需人工确认后清理",
		}).Error; err != nil {
		log.Printf("[proxy-drain] 标记遗留待办失败（用户 %d）: %v", row.UserID, err)
	}
}

type ProxyDrainQueueHealth struct {
	Pending       int64      `json:"pending"`
	Exhausted     int64      `json:"exhausted"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	FrpsAvailable bool       `json:"frps_available"`
	LastErr       string     `json:"last_err,omitempty"`
}

func (s *Services) ProxyDrainQueueHealth() ProxyDrainQueueHealth {
	h := ProxyDrainQueueHealth{FrpsAvailable: s != nil && s.Frps != nil}
	if s == nil || s.DB == nil {
		return h
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", false).Count(&h.Pending).Error; err != nil {
		log.Printf("[proxy-drain] 统计待办数量失败: %v", err)
		return h
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", true).Count(&h.Exhausted).Error; err != nil {
		log.Printf("[proxy-drain] 统计终态待办数量失败: %v", err)
		return h
	}
	var next []time.Time
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("exhausted = ?", false).Order("next_at asc").Limit(1).
		Pluck("next_at", &next).Error; err == nil && len(next) > 0 {
		t := next[0]
		h.NextAttemptAt = &t
	}
	var last model.ProxyDrainPending
	if err := s.DB.Select("last_err").
		Where("last_err <> ''").Order("updated_at desc").First(&last).Error; err == nil {
		h.LastErr = last.LastErr
	}
	return h
}

func (s *Services) retryPendingProxyDrains(ctx context.Context) int {
	if s.DB == nil {
		return 0
	}
	if s.Frps == nil {
		return 0
	}
	now := time.Now()
	var rows []model.ProxyDrainPending
	if err := s.DB.Where("next_at <= ? AND exhausted = ?", now, false).
		Order("next_at asc").Limit(proxyDrainBatchSize).Find(&rows).Error; err != nil {
		log.Printf("[proxy-drain] 读取断流待办失败（本轮跳过）: %v", err)
		return 0
	}

	for i := range rows {
		if ctx.Err() != nil {
			break
		}
		row := rows[i]
		if !s.claimProxyDrain(&row, time.Now()) {
			continue
		}

		req := requestFromPending(row)
		intent, asDeleted := s.proxyDrainIntentState(row)
		switch intent {
		case proxyDrainIntentAbandoned:
			s.clearProxyDrainPending(req.userID, req.intent)
			log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号已被重新启用或再次禁用，状态版本已不是 %d），不再关闭其代理",
				req.userID, row.StatusGen)
			continue
		case proxyDrainIntentUnverifiable:
			continue
		case proxyDrainIntentManual:
			s.markProxyDrainManual(row)
			log.Printf("[proxy-drain] 用户 %d 的断流待办缺少账号标识（升级前遗留），已停止自动断流并保留记录，需人工确认",
				row.UserID)
			continue
		}
		if asDeleted && !req.deleted {
			req.deleted = true
		}

		drainCtx, cancel := context.WithTimeout(ctx, closeProxiesTimeout)
		out := s.runProxyDrain(drainCtx, req)
		cancel()

		if out.abandoned {
			s.clearProxyDrainPending(req.userID, req.intent)
			log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号在断流过程中被重新启用），不再关闭其代理",
				req.userID)
			continue
		}
		if out.unknown || len(out.residual) > 0 {
			s.rescheduleProxyDrain(req, out)
			continue
		}
		s.clearProxyDrainPending(req.userID, req.intent)
		if out.closed > 0 {
			log.Printf("[proxy-drain] 用户 %d 的残留代理已补关（%d 条），待办已清除", req.userID, out.closed)
		}
	}

	var left int64
	if err := s.DB.Model(&model.ProxyDrainPending{}).Where("exhausted = ?", false).Count(&left).Error; err != nil {
		return 0
	}
	return int(left)
}

func (s *Services) ProxyDrainPendingCount() (int64, error) {
	var n int64
	err := s.DB.Model(&model.ProxyDrainPending{}).Where("exhausted = ?", false).Count(&n).Error
	return n, err
}

func (s *Services) StartProxyDrainWorker(ctx context.Context) <-chan struct{} {
	if s.Frps == nil {
		log.Printf("[proxy-drain] 未配置 frps 管理接口：本部署无法主动断开已建立的代理流量，" +
			"删除/禁用账号后残留的转发只能等客户端自己退出。请配置 frps 管理地址以启用断流。")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(proxyDrainRetryInterval)
		defer ticker.Stop()

		if n := s.retryPendingProxyDrains(ctx); n > 0 {
			log.Printf("[proxy-drain] 启动时恢复了 %d 份待办的断流，将继续重试", n)
		}
		s.flushProxyDrainFallback()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := s.retryPendingProxyDrains(ctx); n > 0 {
					log.Printf("[proxy-drain] 仍有 %d 份断流待办未完成，将在下个周期继续重试", n)
				}
				s.flushProxyDrainFallback()
			}
		}
	}()
	return done
}
