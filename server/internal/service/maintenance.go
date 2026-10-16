package service

import (
	"context"
	"log"
	"time"

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
)

// StartMaintenanceWorker 周期清理短期数据（验证码、重置令牌、发件箱终态记录）。
//
// # 为什么需要它
//
// 这些行以前没有任何清理路径：验证码过期、令牌用完、邮件发送失败之后就一直留着
// （发件箱原本只清「已送达且超过保留期」的，failed 的永远不清）。公网服务跑上
// 几个月，这几张表会明显变大，索引也跟着变慢。
func (s *Services) StartMaintenanceWorker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()

		// 启动即清一次：重启频繁的部署也能等到清理机会。
		s.RunMaintenance()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.RunMaintenance()
			}
		}
	}()
}

// RunMaintenance 执行一轮清理。
func (s *Services) RunMaintenance() {
	now := time.Now()

	s.pruneTable("过期验证码", &model.EmailCode{},
		"created_at < ?", now.Add(-emailCodeRetention))
	s.pruneTable("过期重置令牌", &model.PasswordResetToken{},
		"created_at < ?", now.Add(-resetTokenRetention))
	s.pruneTable("失败邮件", &model.MailOutbox{},
		"status = ? AND updated_at < ?", model.MailFailed, now.Add(-mailFailedRetention))
	s.pruneMailOutbox()
}

// pruneTable 按条件分批删除，返回本轮删掉的条数。
//
// 先取一批主键、再按主键删：GORM 的 Delete 不支持 LIMIT，而「一条语句删干净」
// 正是这里要避免的。删不动或删失败都只记日志——清理任务不该把服务拖垮，
// 更不该因为一次数据库抖动就退出。
func (s *Services) pruneTable(name string, dest any, cond string, args ...any) int64 {
	var ids []uint
	if err := s.DB.Model(dest).Where(cond, args...).
		Limit(maintenanceBatchSize).Pluck("id", &ids).Error; err != nil {
		log.Printf("[cleanup] 查询待清理的%s失败: %v", name, err)
		return 0
	}
	if len(ids) == 0 {
		return 0
	}

	res := s.DB.Where("id IN ?", ids).Delete(dest)
	if res.Error != nil {
		log.Printf("[cleanup] 清理%s失败: %v", name, res.Error)
		return 0
	}
	if n := res.RowsAffected; n > 0 {
		// 把「还有剩余」也说出来：只有这一行日志时，看到它到达上限
		// 就知道积压比一轮能清掉的多，需要关注而不是以为已经清完。
		log.Printf("[cleanup] 已清理 %d 条%s（单轮上限 %d，剩余下轮继续）", n, name, maintenanceBatchSize)
	}
	return res.RowsAffected
}
