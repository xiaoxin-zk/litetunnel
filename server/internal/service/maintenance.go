package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	emailCodeRetention   = 24 * time.Hour
	resetTokenRetention  = 24 * time.Hour
	mailFailedRetention  = 7 * 24 * time.Hour
	maintenanceInterval  = time.Hour
	maintenanceBatchSize = 500
	maintenanceBudget    = 5 * time.Second
)

func (s *Services) StartMaintenanceWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()

		s.runMaintenance(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runMaintenance(ctx)
			}
		}
	}()
	return done
}

func (s *Services) RunMaintenance() { s.runMaintenance(context.Background()) }

func (s *Services) runMaintenance(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	deadline := now.Add(maintenanceBudget)

	s.pruneTable(ctx, deadline, "过期验证码", &model.EmailCode{},
		"created_at < ?", now.Add(-emailCodeRetention))
	if ctx.Err() != nil {
		return
	}
	s.pruneTable(ctx, deadline, "过期重置令牌", &model.PasswordResetToken{},
		"created_at < ?", now.Add(-resetTokenRetention))
	if ctx.Err() != nil {
		return
	}
	s.pruneTable(ctx, deadline, "失败邮件", &model.MailOutbox{},
		"status = ? AND updated_at < ?", model.MailFailed, now.Add(-mailFailedRetention))
	if ctx.Err() != nil {
		return
	}
	s.pruneMailOutbox(ctx, deadline)
	if ctx.Err() != nil {
		return
	}
	if days := s.Settings.Int(KeyAuditRetentionDays); days > 0 {
		s.pruneTable(ctx, deadline, "过期审计日志", &model.AuditLog{},
			"created_at < ?", now.AddDate(0, 0, -days))
		if ctx.Err() != nil {
			return
		}
	}
	s.PurgeExpiredLoginFails(now.Add(-loginFailWindow), deadline)
	s.PurgeExpiredStepUpGrants(now)
	s.maybeAutoBackup(now)

	middleware.SweepIdleLimiters()
}

func (s *Services) pruneTable(ctx context.Context, deadline time.Time, name string, dest any, cond string, args ...any) int64 {
	var total int64
	for {
		n := s.pruneBatch(ctx, name, dest, cond, args...)
		total += n
		if n < maintenanceBatchSize {
			break
		}
		if time.Now().After(deadline) {
			var left int64
			if err := s.DB.WithContext(ctx).Model(dest).Where(cond, args...).Count(&left).Error; err != nil {
				log.Printf("[cleanup] 统计 %s 剩余量失败: %v", name, err)
			} else {
				log.Printf("[cleanup] %s 本轮已清理 %d 条，达到时间预算，剩余约 %d 条下轮继续",
					name, total, left)
			}
			break
		}
	}
	if total > 0 {
		log.Printf("[cleanup] 已清理 %d 条%s", total, name)
	}
	return total
}

func (s *Services) pruneBatch(ctx context.Context, name string, dest any, cond string, args ...any) int64 {
	var ids []uint
	if err := s.DB.WithContext(ctx).Model(dest).Where(cond, args...).
		Limit(maintenanceBatchSize).Pluck("id", &ids).Error; err != nil {
		log.Printf("[cleanup] 查询待清理的%s失败: %v", name, err)
		return 0
	}
	if len(ids) == 0 {
		return 0
	}

	res := s.DB.WithContext(ctx).Where("id IN ?", ids).Delete(dest)
	if res.Error != nil {
		log.Printf("[cleanup] 清理%s失败: %v", name, res.Error)
		return 0
	}
	return res.RowsAffected
}
