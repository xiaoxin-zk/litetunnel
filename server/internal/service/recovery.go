package service

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

const recoveryBuffer = 256

type recoveryCounters struct {
	rejected atomic.Uint64
	failed   atomic.Uint64
}

func (s *Services) RecoveryStats() map[string]uint64 {
	return map[string]uint64{
		"queued":   uint64(len(s.recoveryCh)),
		"capacity": uint64(cap(s.recoveryCh)),
		"rejected": s.recoveryCounters.rejected.Load(),
		"failed":   s.recoveryCounters.failed.Load(),
	}
}

func (s *Services) recordRecoveryFailure() {
	if s.recoveryCounters != nil {
		s.recoveryCounters.failed.Add(1)
	}
	log.Printf("[recovery] 后台处理失败，请求可能未进入发件箱；用户需要重新申请")
}

type recoveryRequest struct {
	account   string
	ip        string
	baseURL   string
	emailCode bool
}

func (s *Services) enqueueRecovery(req recoveryRequest) error {
	if len(req.account) > 255 {
		return ErrInvalidParam
	}
	select {
	case s.recoveryCh <- req:
		return nil
	default:
		if s.recoveryCounters != nil {
			s.recoveryCounters.rejected.Add(1)
		}
		log.Printf("[recovery] 请求队列已满，拒绝受理")
		return ErrMailQueueFull
	}
}

func (s *Services) processRecovery(req recoveryRequest) {
	var err error
	if req.emailCode {
		err = s.sendEmailCode(req.account, EmailSceneReset, req.ip)
	} else {
		err = s.requestPasswordReset(req.account, req.ip, req.baseURL)
	}
	if err != nil {
		s.recordRecoveryFailure()
	}
}

func (s *Services) StartRecoveryWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case req := <-s.recoveryCh:
				if ctx.Err() != nil {
					return
				}
				workCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				worker := &Services{DB: s.DB.WithContext(workCtx), Cfg: s.Cfg, Settings: s.Settings, mailWake: s.mailWake, recoveryCounters: s.recoveryCounters}
				worker.processRecovery(req)
				cancel()
			}
		}
	}()
	return done
}
