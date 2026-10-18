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
	// 先更新失败计数，再入队写审计日志。
	//
	// 顺序不能反：队列满时这条日志会被丢弃，而计数不能——它是验证码阈值的
	// 数据源。先记计数也顺带让「日志已落库」成为比「计数已生效」更晚的信号，
	// 外部按日志等待时不会观察到计数还没更新的中间态。
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

// StartLoginLogWriter 启动日志落库协程，直到 ctx 结束。
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
				}
			case <-ticker.C:
				s.PurgeOldLoginLogs(time.Now().AddDate(0, 0, -loginLogRetentionDays))
			}
		}
	}()
	return done
}

// drainLoginLogs 在退出前把缓冲里的日志尽力落库。
func (s *Services) drainLoginLogs() {
	for {
		select {
		case e := <-s.loginLogCh:
			if err := s.DB.Create(&e).Error; err != nil {
				log.Printf("[loginlog] 退出前落库失败（该条日志已丢失）: %v", err)
			}
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

// trackLoginFailure 维护账号级失败计数（验证码判定的数据源）。
//
// 只统计真正的「猜测」：
//   - bad_credentials：密码错，这是爆破信号；
//   - totp_failed：密码对了但动态口令错，同样是一次猜测。
//
// 其余结果一律不计：
//   - locked：我们主动要求验证码，密码还没被校验过，计进去等于自己抬高自己；
//   - disabled：账号本来就不能用，猜对了也进不来；
//   - account_deleted 之类：不是一次登录尝试。
//
// 成功则清零——判定的是「连续」失败，见 loginfail.go。
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

// CountRecentFailedLogins 统计某账号在时间窗内的失败次数。
//
// 只供审计与排查（例如后台识别可疑账号），**不能**用作认证门槛的数据源：
// 它查的是异步登录日志，日志队列满了会丢弃。验证码阈值用的是
// loginFailureCounter（见 loginfail.go）。
func (s *Services) CountRecentFailedLogins(kind, username string, within time.Duration) int64 {
	var n int64
	// 查询失败时返回 0，而 0 在排查语境里正好表示「没有失败记录」，
	// 两者混淆会误导判断，因此必须留痕。
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
