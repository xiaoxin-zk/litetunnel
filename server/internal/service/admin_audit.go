package service

import (
	"log"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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
