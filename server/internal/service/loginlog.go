package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const loginLogBuffer = 2048

const loginLogRetentionDays = 180

type LoginAttempt struct {
	Kind      string
	AccountID uint
	Username  string
	IP        string
	UserAgent string
	Source    string
	Result    string
	Detail    string
}

func (s *Services) RecordLogin(a LoginAttempt) {
	s.trackLoginFailure(a)

	entry := model.LoginLog{
		Kind:      a.Kind,
		AccountID: a.AccountID,
		Username:  truncate(a.Username, 64),
		IP:        truncate(a.IP, 64),
		UserAgent: truncate(a.UserAgent, 255),
		Source:    a.Source,
		Result:    a.Result,
		Detail:    truncate(a.Detail, 255),
	}
	select {
	case s.loginLogCh <- entry:
	default:
		log.Printf("[loginlog] 缓冲已满，丢弃一条登录日志")
	}
}

func (s *Services) StartLoginLogWriter(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.drainLoginLogs()
				return
			case e := <-s.loginLogCh:
				if err := s.DB.Create(&e).Error; err != nil {
					log.Printf("[loginlog] 写入失败: %v", err)
					s.recordAuditFailure(auditScopeLoginLog, err)
				}
			case <-ticker.C:
				s.PurgeOldLoginLogs(time.Now().AddDate(0, 0, -loginLogRetentionDays))
			}
		}
	}()
	return done
}

func (s *Services) drainLoginLogs() {
	for {
		select {
		case e := <-s.loginLogCh:
			if err := s.DB.Create(&e).Error; err != nil {
				log.Printf("[loginlog] 退出前落库失败（该条日志已丢失）: %v", err)
				s.recordAuditFailure(auditScopeLoginLog, err)
			}
		default:
			return
		}
	}
}

func (s *Services) PurgeOldLoginLogs(before time.Time) {
	res := s.DB.Where("created_at < ?", before).Delete(&model.LoginLog{})
	if res.Error != nil {
		log.Printf("[loginlog] 清理历史日志失败: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("[loginlog] 已清理 %d 条超过 %d 天的登录日志",
			res.RowsAffected, loginLogRetentionDays)
	}
}

func (s *Services) ListLoginLogs(kind, result, username string, offset, limit int) ([]model.LoginLog, int64, error) {
	q := s.DB.Model(&model.LoginLog{})
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if result != "" {
		q = q.Where("result = ?", result)
	}
	if username != "" {
		q = q.Where("username LIKE ?", "%"+username+"%")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.LoginLog
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

func (s *Services) trackLoginFailure(a LoginAttempt) {
	if s.loginFails == nil {
		return
	}
	if a.Result == model.LoginResultSuccess {
		s.loginFails.reset(a.Username)
		return
	}
	switch a.Result {
	case model.LoginResultBadCred, model.LoginResultTOTPFail:
		s.loginFails.record(a.Username, time.Now())
	}
}

func (s *Services) CountRecentFailedLogins(kind, username string, within time.Duration) int64 {
	var n int64
	if err := s.DB.Model(&model.LoginLog{}).
		Where("kind = ? AND username = ? AND result <> ? AND created_at > ?",
			kind, username, model.LoginResultSuccess, time.Now().Add(-within)).
		Count(&n).Error; err != nil {
		log.Printf("[loginlog] 统计 %s 账号 %q 最近 %s 的失败登录数失败（返回 0 不代表无失败）: %v",
			kind, username, within, err)
		return 0
	}
	return n
}
