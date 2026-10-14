package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// loginLogBuffer 是登录日志的内存缓冲长度。
// 缓冲满时丢弃而不是阻塞：日志写入绝不能影响登录判定本身。
const loginLogBuffer = 2048

// loginLogRetentionDays 是登录日志保留天数。
// 等保 2.0 要求安全审计记录留存不少于 6 个月。
const loginLogRetentionDays = 180

// LoginAttempt 描述一次登录尝试。
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

// RecordLogin 记录一次登录尝试。成功与失败都要记：
// 失败记录才是发现暴力破解与撞库的依据。
func (s *Services) RecordLogin(a LoginAttempt) {
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

// StartLoginLogWriter 启动日志落库协程，直到 ctx 结束。
func (s *Services) StartLoginLogWriter(ctx context.Context) {
	go func() {
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
				}
			case <-ticker.C:
				s.PurgeOldLoginLogs(time.Now().AddDate(0, 0, -loginLogRetentionDays))
			}
		}
	}()
}

// drainLoginLogs 在退出前把缓冲里的日志尽力落库。
func (s *Services) drainLoginLogs() {
	for {
		select {
		case e := <-s.loginLogCh:
			_ = s.DB.Create(&e).Error
		default:
			return
		}
	}
}

// PurgeOldLoginLogs 清理超过保留期的登录日志。
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

// ListLoginLogs 分页查询登录日志。
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

// CountRecentFailedLogins 统计某账号在时间窗内的失败次数，供后台快速识别可疑账号。
func (s *Services) CountRecentFailedLogins(kind, username string, within time.Duration) int64 {
	var n int64
	_ = s.DB.Model(&model.LoginLog{}).
		Where("kind = ? AND username = ? AND result <> ? AND created_at > ?",
			kind, username, model.LoginResultSuccess, time.Now().Add(-within)).
		Count(&n).Error
	return n
}
