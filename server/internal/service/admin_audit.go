package service

import (
	"log"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// WriteAudit 写入管理员操作审计，返回是否写入成功。
//
// # 为什么不再吞掉错误
//
// 以前这里是 `_ = s.DB.Create(...)`：写失败既没有日志、也没有任何地方能
// 看出来。结果是「管理操作成功、审计记录缺失」这种状态可以静默存在——
// 出事之后去查审计，只会发现那段时间什么都没有，而且分不清是「没人操作」
// 还是「记录没写进去」。
//
// 现在失败会打一条带上下文的错误日志，并把错误返回给调用方。
//
// **刻意没有让审计失败回滚管理操作**：多数管理操作在调用审计之前就已经生效
// （改的是数据库），要保证强一致得把审计并入同一个事务，那是一次范围更大的
// 改动。先做到「失败可见」，是否升级由使用方决定。
func (s *Services) WriteAudit(adminID uint, adminName, action, target, targetID, detail, ip string) error {
	err := s.DB.Create(&model.AuditLog{
		AdminID:   adminID,
		AdminName: adminName,
		Action:    action,
		Target:    target,
		TargetID:  targetID,
		Detail:    truncate(detail, 1000),
		IP:        ip,
	}).Error
	if err != nil {
		log.Printf("[audit] 审计写入失败（管理员 %s，操作 %s，对象 %s/%s）: %v",
			adminName, action, target, targetID, err)
	}
	return err
}

// ListAuditLogs 分页查询审计日志。
func (s *Services) ListAuditLogs(action string, offset, limit int) ([]model.AuditLog, int64, error) {
	q := s.DB.Model(&model.AuditLog{})
	if action != "" {
		q = q.Where("action = ?", action)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.AuditLog
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}
