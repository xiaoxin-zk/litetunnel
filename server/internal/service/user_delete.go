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
	// 注销事务（含用户行锁、密码复核、端口清单收集）单独成一个函数，锁在里面
	// defer 释放。理由与 AdminDeleteUser 完全一致，这里不再重复整段，只强调
	// 与本路径相关的一条：事务提交后账号行已不存在，建隧道不可能再成功；
	// 而随后的断流会访问 frps 管理接口，并在内部取**同一把**用户锁，
	// 因此锁必须在进入断流之前、且以 defer 的形式释放（panic 也能放掉）。
	ports, err := s.deleteAccountTx(userID, password)
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
	// 状态代次随之清掉（原因见 AdminDeleteUser 同一处）。
	s.forgetUserStatusGen(userID)
	// 会话同样要清：数据库里的会话行已经随事务删除，但插件热路径
	// （onNewUserConn）查的是内存会话表。账号都注销了还能继续建新连接，
	// 是最不该出现的一种。
	s.Runtime.DropUserSessions(userID)

	// 已建立的 frps 代理同样要主动关闭，理由与管理端删除一致：账号删掉只
	// 拦得住新连接，已经在转发的数据流会一直跑到客户端自己退出。注销是
	// 用户主动要求「彻底删掉」，更不该留一条还在跑的隧道。
	//
	// 事务提交后账号行已不存在，users.state_version 无从读取，因此走
	// CloseDeletedUserProxies（按前缀 + 代理实例身份尽力关闭）而不是
	// CloseUserProxies（它需要 gen 做跨实例见证）。
	// 关闭失败不影响注销结果，残留数量由该函数记日志。
	s.closeUserProxiesAfterDelete(userID)

	// 隧道没了，主机防火墙上的放行规则也要收回。
	//
	// 不会漏掉「并发新建、晚于本事务快照」的隧道：建隧道的事务同样要先锁
	// 用户行，本事务提交前它插不进来，提交后它读到账号已不存在而整体失败。
	s.closePorts(ports)
	return nil
}

// deleteAccountTx 在用户锁内完成注销事务，返回需要回收的端口清单。
func (s *Services) deleteAccountTx(userID uint, password string) ([]portProto, error) {
	// 与「给自己建隧道」互斥（见 userLock）：只把端口读取放进事务还不够，
	// READ COMMITTED 下在端口查询之后提交的新隧道仍可能被删掉而漏出回收清单。
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	// 端口在**事务内**读取，删完之后再由调用方回收（见 DeleteAccount）。
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
		return nil, err
	}
	return ports, nil
}
