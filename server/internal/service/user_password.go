package service

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// UpdatePassword 修改密码。
//
// 改密后自增 TokenVersion，使此前签发的所有令牌立即失效——
// JWT 无状态，这是让「改密即全端下线」成立的唯一办法。
func (s *Services) UpdatePassword(userID uint, oldPwd, newPwd string) error {
	if len(newPwd) < 8 {
		return fmt.Errorf("%w: 新密码长度不得少于 8 位", ErrInvalidParam)
	}
	// bcrypt 刻意做得慢（防离线爆破），放在事务外计算，避免长时间持锁。
	hashed, err := auth.HashPassword(newPwd)
	if err != nil {
		return err
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁用户行：改密与「重置邮件送达后激活」都以这一行为序。
		//
		// 密码校验放在锁内重做，而不是锁外先验一遍：并发改密时，锁外的
		// 校验基于旧快照，等本事务拿到行锁时密码可能已被别的请求改掉，
		// 「原密码正确」的那份结论已经作废。锁内重读并校验，保证改密
		// 一定基于当前密码。
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&locked, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if !auth.VerifyPassword(locked.Password, oldPwd) {
			return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
		}
		if auth.VerifyPassword(locked.Password, newPwd) {
			return fmt.Errorf("%w: 新密码不能与当前密码相同", ErrInvalidParam)
		}
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error; err != nil {
			return err
		}
		// 已建立的客户端会话同步置为离线：只递增 token_version 只能让
		// 网页 JWT 失效，frpc 用的是 client_secret，不受它影响。
		if err := revokeClientSessionsTx(tx, userID); err != nil {
			return err
		}
		// 旧的重置链接与排队中的重置邮件一并作废：改密之后它们不该还能用。
		return revokePasswordResetTx(tx, userID, locked.Email)
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	// 内存会话必须一起清：插件热路径先查内存，命中后只校验配额就放行，
	// 根本不会读数据库。不清的话，改完密码的 frpc 仍能继续接受新连接。
	s.Runtime.DropUserSessions(userID)
	return nil
}
