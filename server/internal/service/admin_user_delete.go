package service

import (
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// AdminDeleteUser 删除用户及其全部隧道与流量记录。
func (s *Services) AdminDeleteUser(id uint) error {
	// 与「给该用户建隧道」互斥（见 userLock）。
	//
	// 只把端口读取放进事务还不够：PostgreSQL 的 READ COMMITTED 下，
	// 一条在端口查询之后、删除语句之前提交的新隧道，仍可能被 DELETE 删掉
	// 而没进回收清单。持有用户锁后，建隧道要么先完成（端口已在清单里），
	// 要么等删除结束——后者会因为账号已不存在而失败。
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	// 端口在**事务内**读取，删完之后再用（见下面 closePorts 的位置）。
	var ports []portProto

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁住用户行：userLock 只在进程内互斥，多副本下挡不住另一台实例
		// 同时在给这个账号建隧道。建隧道的事务也锁这一行（见 CreateTunnel），
		// 锁上之后两者只剩先后关系——要么隧道已在端口清单里，要么建隧道
		// 等删号提交后发现账号不存在而失败，不会留下孤儿隧道。
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var tunnels []model.Tunnel
		if err := tx.Where("user_id = ? AND remote_port > 0", id).Find(&tunnels).Error; err != nil {
			return err
		}
		ports = portsOfTunnels(tunnels)
		if err := tx.Where("user_id = ?", id).Delete(&model.Tunnel{}).Error; err != nil {
			return err
		}
		// 清单修订号随账号一起清掉：删隧道会让触发器再补一行
		// （见 store.ensureTunnelListRevTriggers），不删就是一条永久孤儿。
		if err := tx.Where("user_id = ?", id).Delete(&model.TunnelListRev{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.TrafficDaily{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.ClientSession{}).Error; err != nil {
			return err
		}
		// 清零代次标记按用户 ID 保存：不删的话会留下永久孤儿行
		// （用户 ID 可能被复用，旧标记还会干扰新用户的代次判断）。
		if err := tx.Where("user_id = ?", id).Delete(&model.TrafficResetMark{}).Error; err != nil {
			return err
		}
		// 重置令牌、验证码与待发凭据邮件一并清理（与自助注销共用）。
		if err := purgeAccountCredentialsTx(tx, id, u.Email); err != nil {
			return err
		}
		return tx.Delete(&model.User{}, id).Error
	})
	if err != nil {
		return err
	}

	// ---- 事务提交之后再做这些 ----
	//
	// 放在事务回调里做会有两个问题：
	//   - 事务可能提交失败，而内存已经被清了（缓存与库不一致）；
	//   - 在多连接数据库上，并发插件回调可能在这段时间里重新读到旧用户
	//     并登记会话，事务提交后又留下一条内存会话。
	//
	// 内存态清理，避免已删除用户仍占用超额/禁用标记或身份缓存。
	// 所有管理路径写准入标记前都递增版本号（见 Runtime.guardVer），
	// 让在途的后台刷新识别「快照已过时」并让路。
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(id, false)
	s.Runtime.SetUserBlocked(id, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	// 会话同样要清：数据库里的会话行已经随事务删除，但插件热路径
	// 查的是内存会话表，残留的话已登录的 frpc 仍会被放行新连接——
	// 账号都删了还在跑，这是最不该出现的一种。
	s.Runtime.DropUserSessions(id)

	// 隧道没了，主机防火墙上的放行规则也要收回，否则会一直留在那里。
	//
	// 放在事务提交之后：回收失败（helper 不可达、端口受保护）不该让
	// 已经完成的删除回滚；失败会记日志，由人工清理。
	//
	// 并发建隧道的窗口已由事务开头的用户行锁关掉：建隧道的事务同样要先锁
	// 用户行（见 createTunnelLocked 里的 reloadUserWithGroupTx），本事务提交
	// 之前它插不进来；提交之后它重读用户会得到「不存在」而整体失败。
	// 所以 ports 与这次 DELETE 删掉的隧道是同一批，不会漏出孤儿端口。
	s.closePorts(ports)
	return nil
}
