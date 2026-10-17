package service

import (
	"context"
	"log"
	"time"
)

const recoveryBuffer = 256

// 请求预处理队列不含凭据，重启前尚未写入发件箱的请求需要用户重新申请。
// 已写入发件箱的邮件仍由持久化队列保证重试与恢复。
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
		log.Printf("[recovery] 请求处理失败，请稍后重新申请")
	}
}

// StartRecoveryWorker 与 SMTP worker 独立，防止慢投递阻塞请求预处理。
func (s *Services) StartRecoveryWorker(ctx context.Context) {
	go func() {
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
				worker := &Services{DB: s.DB.WithContext(workCtx), Cfg: s.Cfg, Settings: s.Settings, mailWake: s.mailWake}
				worker.processRecovery(req)
				cancel()
			}
		}
	}()
}
