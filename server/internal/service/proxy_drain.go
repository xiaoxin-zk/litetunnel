package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) CloseUserProxies(ctx context.Context, userID uint, gen uint64, notAfter time.Time) {
	s.closeUserProxiesWithIntent(ctx, userID, gen, notAfter, "")
}

func (s *Services) closeUserProxiesWithIntent(ctx context.Context, userID uint, gen uint64, notAfter time.Time, intent string) {
	s.drainProxies(ctx, proxyDrainRequest{
		userID:   userID,
		prefix:   FrpUserOf(userID) + ".",
		gen:      gen,
		notAfter: notAfter,
		intent:   intent,
	})
}

const closeProxiesTimeout = 15 * time.Second

func (s *Services) CloseDeletedUserProxies(ctx context.Context, userID uint) {
	row, found, err := s.deletedDrainIntent(userID)
	if err != nil {
		log.Printf("[proxy-drain] 读取已删账号 %d 的断流待办失败，保留原现场并跳过本次断流: %v", userID, err)
		return
	}
	if found {
		switch state, _ := s.proxyDrainIntentState(row); state {
		case proxyDrainIntentUnverifiable:
			log.Printf("[proxy-drain] 已删账号 %d 的身份读取失败，跳过即时断流，保留待办由后台重试", userID)
			return
		case proxyDrainIntentAbandoned:
			log.Printf("[proxy-drain] 已删账号 %d 的断流意图已作废（账号行仍存在或标识已变），跳过即时断流", userID)
			return
		case proxyDrainIntentManual:
			log.Printf("[proxy-drain] 已删账号 %d 的断流待办无法自动核验身份，跳过自动断流，转人工确认", userID)
			return
		}
	}

	var req proxyDrainRequest
	if found {
		req = requestFromPending(row)
	} else {
		req = proxyDrainRequest{
			userID:     userID,
			prefix:     FrpUserOf(userID) + ".",
			deleted:    true,
			noRegister: true,
		}
	}
	out := s.drainProxies(ctx, req)
	switch {
	case out.unknown:
		log.Printf("[service] 账号 %d 已删除，但拉取代理列表失败，残留代理数量无法确认（已记入待办由后台继续重试）；同时靠客户端重连被拒兜底，请人工排查",
			userID)
	case len(out.residual) > 0:
		log.Printf("[service] 账号 %d 已删除，但仍有 %d 个代理未能关闭（frps 管理接口不可用或实例身份不可判定），已记入待办由后台继续重试；同时靠客户端重连被拒兜底，请人工排查",
			userID, len(out.residual))
	}
}

func (s *Services) deletedDrainIntent(userID uint) (model.ProxyDrainPending, bool, error) {
	var row model.ProxyDrainPending
	if s.DB == nil {
		return row, false, errors.New("数据库未初始化")
	}
	if err := s.DB.Where("user_id = ? AND deleted = ?", userID, true).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return row, false, nil
		}
		return row, false, err
	}
	return row, true, nil
}

func (s *Services) closeUserProxiesAfterDelete(userID uint) {
	ctx, cancel := context.WithTimeout(context.Background(), closeProxiesTimeout)
	defer cancel()
	s.CloseDeletedUserProxies(ctx, userID)
}

type proxyDrainRequest struct {
	userID      uint
	prefix      string
	gen         uint64
	notAfter    time.Time
	deleted     bool
	attempts    int
	known       []proxyDrainTarget
	intent      string
	noRegister  bool
	incarnation string
}

type proxyDrainOutcome struct {
	residual      []proxyDrainTarget
	unknown       bool
	abandoned     bool
	closed        int
	lastErr       string
	suspects      []string
	closedTargets []proxyDrainTarget
}

func (s *Services) drainProxies(ctx context.Context, req proxyDrainRequest) proxyDrainOutcome {
	var out proxyDrainOutcome
	if s.Frps == nil {
		if req.intent == "" && !req.noRegister {
			req.intent = s.recordProxyDrainPending(req)
		}
		out.unknown = true
		out.lastErr = "frps 管理客户端未初始化，断流结果未知"
		if req.noRegister {
			log.Printf("[service] 未配置 frps 管理接口，用户 %d 的断流结果未知（noRegister，不登记长期待办）", req.userID)
		} else {
			log.Printf("[service] 未配置 frps 管理接口，用户 %d 的断流结果未知，已保留待办", req.userID)
		}
		return out
	}
	if req.prefix == "" {
		req.prefix = FrpUserOf(req.userID) + "."
	}

	if req.intent == "" && !req.noRegister {
		req.intent = s.recordProxyDrainPending(req)
	}
	if req.intent == "" && !req.noRegister {
		if s.drainFallback != nil {
			s.drainFallback.enqueue(req)
			log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败，已放入进程内补偿队列（数据库恢复后自动补写）", req.userID)
		} else {
			log.Printf("[proxy-drain] 用户 %d 的断流待办落库失败且无补偿队列：本次若也没关干净，重启后将没有任何补偿机会", req.userID)
		}
	}

	out = s.runProxyDrain(ctx, req)
	switch {
	case out.abandoned:
		s.clearProxyDrainPending(req.userID, req.intent)
		log.Printf("[proxy-drain] 用户 %d 的断流意图已作废（账号在断流期间被重新启用），不再关闭其代理", req.userID)
	case out.unknown || len(out.residual) > 0:
		s.rescheduleProxyDrain(req, out)
	default:
		s.clearProxyDrainPending(req.userID, req.intent)
		if out.closed > 0 {
			log.Printf("[proxy-drain] 用户 %d 的代理已全部关闭（%d 条），无残留", req.userID, out.closed)
		}
	}
	return out
}

func (s *Services) runProxyDrain(ctx context.Context, req proxyDrainRequest) proxyDrainOutcome {
	var out proxyDrainOutcome

	if !req.deleted {
		if cached := s.userStatusGen(req.userID); cached != 0 && cached != req.gen {
			log.Printf("[user] 用户 %d 的状态在断流开始前已变更，跳过本次断流", req.userID)
			out.abandoned = true
			return out
		}
	}

	cache := newProxySnapshotCache(s)
	if len(req.known) > 0 {
		return s.closeDrainTargets(ctx, req, cache, req.known)
	}

	snap, err := cache.current(ctx)
	if err != nil {
		log.Printf("[user] 拉取代理列表失败，本次无法主动断流（新连接仍会被拒，已记入待办等 frps 恢复后重试）: %v", err)
		if req.deleted {
			log.Printf("[service] 账号 %d 已删除且代理列表拉取失败，残留代理数量无法确认，靠客户端重连被拒兜底", req.userID)
		}
		out.unknown = true
		out.lastErr = err.Error()
		return out
	}

	return s.closeDrainTargets(ctx, req, cache, snap.discoveryTargets(req.userID, req.prefix, req.notAfter))
}

func (s *Services) closeDrainTargets(ctx context.Context, req proxyDrainRequest, cache *proxySnapshotCache, candidates []proxyDrainTarget) proxyDrainOutcome {
	var out proxyDrainOutcome
	for i, t := range candidates {
		if ctx.Err() != nil {
			out.residual = append(out.residual, candidates[i:]...)
			out.lastErr = "断流超出时间预算，剩余代理未处理"
			return out
		}
		step, errMsg := s.closeDrainedProxy(ctx, req, cache, t)
		switch step {
		case drainStepClosed:
			out.closed++
			out.closedTargets = append(out.closedTargets, t)
		case drainStepGone:
		case drainStepResidual:
			out.residual = append(out.residual, t)
			if out.lastErr == "" && errMsg != "" {
				out.lastErr = errMsg
			}
		case drainStepAbandoned:
			out.abandoned = true
			return out
		}
	}
	if out.lastErr == "" && cache.listErr != nil {
		out.lastErr = cache.listErr.Error()
	}

	return s.verifyClosedProxies(ctx, req, out)
}

func (s *Services) verifyClosedProxies(ctx context.Context, req proxyDrainRequest, out proxyDrainOutcome) proxyDrainOutcome {
	if len(out.closedTargets) == 0 || ctx.Err() != nil {
		return out
	}
	fresh := newProxySnapshotCache(s)
	snap, err := fresh.current(ctx)
	if err != nil {
		log.Printf("[user] 用户 %d 关闭 %d 个代理后无法复查实例身份（列表拉取失败），保留待办等待重试: %v",
			req.userID, len(out.closedTargets), err)
		out.unknown = true
		out.residual = append(out.residual, out.closedTargets...)
		if out.lastErr == "" {
			out.lastErr = err.Error()
		}
		return out
	}

	var sameIdentity []string
	for _, t := range out.closedTargets {
		cur, ok := snap.lookup(t.Name)
		if !ok {
			continue
		}
		reborn := targetOf(cur)
		if !reborn.identifiable() || t.matches(cur) {
			sameIdentity = append(sameIdentity, t.Name)
			continue
		}
		msg := fmt.Sprintf("代理 %q 关闭后以另一个实例身份重新出现（clientID/lastStartAt 已变），"+
			"可能误关了新实例或客户端已重连", t.Name)
		log.Printf("[proxy-drain][ALERT] 用户 %d: %s；该代理已转为**人工待办**（不再自动重试），请人工核对",
			req.userID, msg)
		s.countProxyDrainRaceSuspect(t.Name)
		out.suspects = append(out.suspects, t.Name)
		out.residual = append(out.residual, t)
		if out.lastErr == "" {
			out.lastErr = msg
		}
	}
	if len(sameIdentity) > 0 {
		log.Printf("[user] 用户 %d 的 %d 个代理在关闭请求成功后仍在列表中（实例身份相同）：%s；"+
			"可能是 frps 列表的可见性延迟，反复出现请人工核对 frps 与宿主机状态",
			req.userID, len(sameIdentity), strings.Join(sameIdentity, ", "))
	}
	return out
}

type ProxyDrainRaceHealth struct {
	Instance       string   `json:"instance,omitempty"`
	Suspects       uint64   `json:"suspects"`
	Recent         []string `json:"recent,omitempty"`
	ManualPending  int64    `json:"manual_pending"`
	ManualSuspects []string `json:"manual_suspects,omitempty"`
}

const drainRaceRecentMax = 16

func (s *Services) countProxyDrainRaceSuspect(name string) {
	if s == nil {
		return
	}
	s.drainRaceSuspects.Add(1)
	if name == "" {
		return
	}
	s.drainRaceMu.Lock()
	defer s.drainRaceMu.Unlock()
	s.drainRaceRecent = append(s.drainRaceRecent, name)
	if over := len(s.drainRaceRecent) - drainRaceRecentMax; over > 0 {
		s.drainRaceRecent = append(s.drainRaceRecent[:0], s.drainRaceRecent[over:]...)
	}
}

func (s *Services) ProxyDrainRaceHealth() ProxyDrainRaceHealth {
	if s == nil {
		return ProxyDrainRaceHealth{}
	}
	s.drainRaceMu.Lock()
	recent := append([]string(nil), s.drainRaceRecent...)
	s.drainRaceMu.Unlock()
	h := ProxyDrainRaceHealth{
		Instance: s.instanceID,
		Suspects: uint64(s.drainRaceSuspects.Load()),
		Recent:   recent,
	}
	if s.DB == nil {
		return h
	}
	if err := s.DB.Model(&model.ProxyDrainPending{}).
		Where("manual_review = ?", true).Count(&h.ManualPending).Error; err != nil {
		log.Printf("[proxy-drain] 统计人工待办数量失败（指标里这一项会偏低）: %v", err)
	}
	var rows []model.ProxyDrainPending
	if err := s.DB.Select("suspects").
		Where("manual_review = ?", true).
		Order("updated_at desc").Limit(drainRaceRecentMax).Find(&rows).Error; err != nil {
		log.Printf("[proxy-drain] 读取人工待办名单失败（指标里这一项会缺失）: %v", err)
		return h
	}
	for _, row := range rows {
		h.ManualSuspects = append(h.ManualSuspects, decodeProxyDrainSuspects(row.Suspects)...)
	}
	return h
}

type proxyDrainStep int

const (
	drainStepClosed proxyDrainStep = iota
	drainStepGone
	drainStepResidual
	drainStepAbandoned
)

func (s *Services) closeDrainedProxy(ctx context.Context, req proxyDrainRequest, cache *proxySnapshotCache, t proxyDrainTarget) (proxyDrainStep, string) {
	if !t.identifiable() {
		log.Printf("[service] 用户 %d 的代理 %q 缺少 clientID 与 lastStartAt，身份不可判定，跳过关闭，待下一轮/兜底",
			req.userID, t.Name)
		return drainStepResidual, ""
	}

	lock := s.userLock(req.userID)
	lock.Lock()
	defer lock.Unlock()

	if !req.deleted {
		if cached := s.userStatusGen(req.userID); cached != 0 && cached != req.gen {
			log.Printf("[user] 用户 %d 的状态在断流过程中已变更，停止关闭剩余代理（避免误伤重新启用后的新代理）", req.userID)
			return drainStepAbandoned, ""
		}
		dbGen, err := s.userStateVersionFromDB(req.userID)
		if err == nil {
			if dbGen != req.gen {
				log.Printf("[user] 用户 %d 的状态在其他实例上已变更（版本 %d ≠ %d），停止关闭剩余代理",
					req.userID, dbGen, req.gen)
				return drainStepAbandoned, ""
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[user] 用户 %d 的状态版本读取失败，跳过关闭并保留待办: %v", req.userID, err)
			return drainStepResidual, err.Error()
		}
	}

	cur, ok, err := cache.lookup(ctx, t.Name)
	if err != nil {
		log.Printf("[user] 关闭代理 %q 前复查状态失败，跳过以避免误关新实例: %v", t.Name, err)
		return drainStepResidual, err.Error()
	}
	if !ok {
		log.Printf("[user] 代理 %q 已从 frps 列表消失，无需关闭", t.Name)
		return drainStepGone, ""
	}
	if !t.matches(cur) {
		log.Printf("[user] 代理 %q 的实例身份已变化，跳过关闭", t.Name)
		return drainStepGone, ""
	}

	if err := s.Frps.CloseProxy(ctx, t.Name); err != nil {
		log.Printf("[user] 关闭用户 %d 的代理 %q 失败: %v", req.userID, t.Name, err)
		return drainStepResidual, err.Error()
	}
	log.Printf("[user] 已关闭用户 %d 的代理 %q", req.userID, t.Name)
	return drainStepClosed, ""
}

func topLevelPrefix(name, prefix string) bool {
	return strings.HasPrefix(name, prefix)
}
