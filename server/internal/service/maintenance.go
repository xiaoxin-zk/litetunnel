package service

import (
	"context"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 各类短期记录与凭据的保留期。
//
// 都远长于它们自身的有效期（验证码 10 分钟、令牌 30 分钟），留一段时间是为了
// 排查「用户说没收到码 / 链接点不开」这类问题；但必须有上限，否则公网上的
// 注册与找回密码请求会一直堆积，表与索引持续膨胀。
const (
	// emailCodeRetention 是邮箱验证码的保留期。
	emailCodeRetention = 24 * time.Hour
	// resetTokenRetention 是重置令牌的保留期。
	resetTokenRetention = 24 * time.Hour
	// mailFailedRetention 是**发送失败**邮件的保留期。
	// 比已送达的长：它们需要人工看一眼（多半是 SMTP 配置错了）。
	mailFailedRetention = 7 * 24 * time.Hour
	// maintenanceInterval 是清理任务的执行间隔。
	maintenanceInterval = time.Hour
	// maintenanceBatchSize 是单轮**单表**的删除上限。
	//
	// 限批而不是一次删干净：一次性大删会长时间占住写锁（SQLite 更是整库阻塞），
	// 在业务高峰期尤其危险。清理是后台任务，慢一点没关系，影响线上请求才是问题。
	maintenanceBatchSize = 500
	// maintenanceBudget 是单轮维护的时间预算。
	//
	// 只做「一轮一批」的话，过期记录的产生速度长期高于清理速度时积压会一直涨。
	// 在预算内连续分批既能追上积压，又不会让一次维护长时间占住数据库。
	maintenanceBudget = 5 * time.Second
)

// StartMaintenanceWorker 周期清理短期数据（验证码、重置令牌、发件箱终态记录）。
//
// # 为什么需要它
//
// 这些行以前没有任何清理路径：验证码过期、令牌用完、邮件发送失败之后就一直留着
// （发件箱原本只清「已送达且超过保留期」的，failed 的永远不清）。公网服务跑上
// 几个月，这几张表会明显变大，索引也跟着变慢。
func (s *Services) StartMaintenanceWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()

		// 启动即清一次：重启频繁的部署也能等到清理机会。
		//
		// 传 ctx 而不是 Background：停机可能正好赶上这一轮，而每一轮
		// 最长可跑 maintenanceBudget。中途检查让关闭阶段不必等满预算，
		// 剩余的表由下次启动继续清（删除是幂等的）。
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

// RunMaintenance 执行一轮清理（不响应停机信号，供测试与一次性调用）。
func (s *Services) RunMaintenance() { s.runMaintenance(context.Background()) }

// runMaintenance 在给定的上下文中执行一轮清理：每一步开始前检查是否已取消。
func (s *Services) runMaintenance(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	// 整个一轮共享一个预算，而不是每张表各算一次：后者在多表同时积压时
	// 会把一次维护拖成好几倍时长。
	deadline := now.Add(maintenanceBudget)

	// 每个查询都带上停机上下文：ctx 取消后，正在排队的 SQL 会立刻返回，
	// 而不是等数据库/驱动自己的超时。否则 svc.Close() 关闭连接池时，
	// 这些语句可能正持有连接，形成「等待 worker → worker 等数据库」的僵局。
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
	// 账号级失败计数（见 loginfail_db.go）：按用户名增长，窗口过后就没用了。
	// 与上面几张表不同，它只影响「是否要出验证码」的强度，不承担审计，
	// 所以过期即可删，不必保留观察期。共用同一个 deadline：它的量级取决于
	// 过去半小时失败过的账号数，被海量随机用户名灌过之后可能很大。
	s.PurgeExpiredLoginFails(now.Add(-loginFailWindow), deadline)

	// 限流器的空闲桶：请求路径上只在有流量时才顺手清理，流量退潮后
	// 就轮不到它了。这里兜底，顺带让「没有 gc 协程」的方案成立。
	middleware.SweepIdleLimiters()
}

// pruneTable 按条件分批删除，返回本轮删掉的条数。
//
// 先取一批主键、再按主键删：GORM 的 Delete 不支持 LIMIT，而「一条语句删干净」
// 正是这里要避免的。删不动或删失败都只记日志——清理任务不该把服务拖垮，
// 更不该因为一次数据库抖动就退出。
func (s *Services) pruneTable(ctx context.Context, deadline time.Time, name string, dest any, cond string, args ...any) int64 {
	var total int64
	for {
		n := s.pruneBatch(ctx, name, dest, cond, args...)
		total += n
		// 这一批没装满，说明已经清空。
		if n < maintenanceBatchSize {
			break
		}
		if time.Now().After(deadline) {
			// 到预算就把剩余量说出来：只有「已清理 N 条」的日志时，
			// 看不出积压是刚清完还是一直在涨。
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

// pruneBatch 删一批（最多 maintenanceBatchSize 条），返回本次删掉的条数。
//
// 单独保留「一批」这一层：一次性大删会长时间占住写锁（SQLite 更是整库阻塞），
// 连续分批既能把积压清干净，又不会让单次语句过大。
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
