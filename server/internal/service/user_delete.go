package service

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// DeleteAccount 用户注销自己的账号。
//
// 需要提供登录密码二次确认：注销不可恢复，必须防止令牌被盗后被恶意注销。
// 关联数据一并清理，避免留下悬空记录。
func (s *Services) DeleteAccount(userID uint, password string) error {
	// 与「给自己建隧道」互斥（见 userLock）：只把端口读取放进事务还不够，
	// READ COMMITTED 下在端口查询之后提交的新隧道仍可能被删掉而漏出回收清单。
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	// 端口在**事务内**读取，删完之后再用（见下面 closePorts 的位置）。
	var ports []portProto

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁住用户行，与「给该账号建隧道」的事务串行（那里也锁这一行）。
		// 只靠进程内的 userLock 挡不住另一台实例：它可能在删号事务删完隧道
		// 之后、提交之前插入一条新隧道，那条隧道会残留且不在回收清单里。
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&locked, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// 密码校验放在锁内：事务外先验一遍的话，并发改密会让「密码正确」的
		// 结论作废——注销必须基于当前密码，而不是请求开始时的旧快照。
		if !auth.VerifyPassword(locked.Password, password) {
			return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
		}
		var tunnels []model.Tunnel
		if err := tx.Where("user_id = ? AND remote_port > 0", userID).Find(&tunnels).Error; err != nil {
			return err
		}
		ports = portsOfTunnels(tunnels)
		if err := tx.Where("user_id = ?", userID).Delete(&model.Tunnel{}).Error; err != nil {
			return err
		}
		// 清单修订号随账号一起清掉：删隧道会让触发器再补一行
		// （见 store.ensureTunnelListRevTriggers），不删就是一条永久孤儿。
		if err := tx.Where("user_id = ?", userID).Delete(&model.TunnelListRev{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficDaily{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.ClientSession{}).Error; err != nil {
			return err
		}
		// 清零代次标记同样是按用户 ID 保存的，随账号一起清掉。
		if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficResetMark{}).Error; err != nil {
			return err
		}
		// 凭据类数据（重置令牌、邮箱验证码、待发凭据邮件）与管理员
		// 删除路径共用同一套清理，避免两条路径各行其是、漏掉其中一类。
		if err := purgeAccountCredentialsTx(tx, userID, locked.Email); err != nil {
			return err
		}
		// 兑换流水与登录日志保留：它们属于审计数据，删除会让风控出现盲区。
		return tx.Delete(&model.User{}, userID).Error
	})
	if err != nil {
		return err
	}

	// ---- 事务提交之后再做这些 ----
	//
	// 内存清理放进事务回调里的话，事务一旦失败就会出现「缓存已清、库里还在」
	// 的不一致；多连接数据库上还可能与并发回调抢跑。
	// 注销也是管理路径的直写：先递增版本号让在途的后台刷新让路。
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(userID, false)
	s.Runtime.SetUserBlocked(userID, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	// 会话同样要清：数据库里的会话行已经随事务删除，但插件热路径
	// （onNewUserConn）查的是内存会话表。账号都注销了还能继续建新连接，
	// 是最不该出现的一种。
	s.Runtime.DropUserSessions(userID)

	// 隧道没了，主机防火墙上的放行规则也要收回。
	//
	// 不会漏掉「并发新建、晚于本事务快照」的隧道：建隧道的事务同样要先锁
	// 用户行，本事务提交前它插不进来，提交后它读到账号已不存在而整体失败。
	s.closePorts(ports)
	return nil
}
