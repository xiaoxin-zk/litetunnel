package service

// 本文件是「账号生命周期协调器」：把一个账号从系统里彻底移除。
//
// # 为什么要把两条删除路径的公共部分收在一处
//
// 管理员删除（AdminDeleteUser）与用户自助注销（DeleteAccount）在事务里做的事
// 完全一样：锁用户行、收集端口清单、删隧道/清单修订号/流量/会话/清零标记、
// 清凭据类数据、最后删账号行。两条路径各自维护一份时，任何一边漏掉一步都会
// 留下孤儿数据，而且很难被发现——孤儿行不会报错，只是慢慢积累。
//
// 缺陷 1（删号不断流）正是这个结构的产物：事务提交之后的「善后」步骤
// （内存清理 → 断流 → 回收防火墙端口）也被复制了两份，于是加断流时两处都要
// 记得改。把「事务」与「善后」各自收成一个函数之后，新增一个善后步骤只需改
// 一处，两条路径自动一致。
//
// # 为什么事务与善后必须分成两个函数，且锁只在事务里
//
// 事务提交后账号行已不存在，建隧道不可能再成功，用户锁没有继续占着的理由；
// 而善后里的断流要访问 frps 管理接口（最长十几秒），并且 closeUserProxies
// 内部会按代理逐条取**同一把**用户锁——在同一函数里持锁调用会自死锁
// （sync.Mutex 不可重入）。
//
// 锁用 defer 释放而不是「提交后手写 Unlock」：事务回调里一旦 panic，手写的
// 那行永远执行不到，那把分片锁会被永久占住，之后落到同一分片的所有建隧道/
// 删号请求全部挂死。拆成独立函数后 defer 一定会生效。

import (
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// accountPurgeTx 在调用方已持有用户锁的前提下，把账号及其关联数据全部删掉，
// 返回需要回收的防火墙端口清单。
//
// 调用方必须持有 s.userLock(userID)：这里只做数据库操作，不做加锁。
// 把加锁留给调用方是为了让「锁罩住的范围」在调用点可见——锁必须只罩住
// 事务，不能延伸到善后步骤（见本文件开头的说明）。
//
// verify 非空时在锁内、事务内复核密码：注销必须基于**当前**密码，而不是
// 请求开始时的旧快照（并发改密会让事务外的校验结论作废）。
func accountPurgeTx(tx *gorm.DB, userID uint, verify func(u *model.User) error) ([]portProto, error) {
	// 锁住用户行：userLock 只在进程内互斥，多副本下挡不住另一台实例
	// 同时在给这个账号建隧道。建隧道的事务也锁这一行（见 CreateTunnel），
	// 锁上之后两者只剩先后关系——要么隧道已在端口清单里，要么建隧道
	// 等删号提交后发现账号不存在而失败，不会留下孤儿隧道。
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, userID).Error; err != nil {
		// 账号不存在时统一成 ErrNotFound（管理端据此返回 404、自助注销据此
		// 返回「用户不存在」），而不是把 gorm 的原始错误透到接口层。
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if verify != nil {
		if err := verify(&u); err != nil {
			return nil, err
		}
	}

	// 端口在**事务内**读取：删完之后再由调用方回收（见 purgeAccountAfterCommit）。
	var tunnels []model.Tunnel
	if err := tx.Where("user_id = ? AND remote_port > 0", userID).Find(&tunnels).Error; err != nil {
		return nil, err
	}
	ports := portsOfTunnels(tunnels)

	if err := tx.Where("user_id = ?", userID).Delete(&model.Tunnel{}).Error; err != nil {
		return nil, err
	}
	// 清单修订号随账号一起清掉：删隧道会让触发器再补一行
	// （见 store.ensureTunnelListRevTriggers），不删就是一条永久孤儿。
	if err := tx.Where("user_id = ?", userID).Delete(&model.TunnelListRev{}).Error; err != nil {
		return nil, err
	}
	if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficDaily{}).Error; err != nil {
		return nil, err
	}
	// 会话行必须删：插件热路径在内存未命中时会回查这张表
	// （见 FindTrustedClientSession），留着它等于给已删账号留一条准入依据。
	if err := tx.Where("user_id = ?", userID).Delete(&model.ClientSession{}).Error; err != nil {
		return nil, err
	}
	// 清零代次标记按用户 ID 保存：不删的话会留下永久孤儿行
	// （用户 ID 可能被复用，旧标记还会干扰新用户的代次判断）。
	if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficResetMark{}).Error; err != nil {
		return nil, err
	}
	// 重置令牌、验证码与待发凭据邮件一并清理。留着的话用户会收到指向
	// 不存在账号的重置邮件，队列还会为一个不存在的账号反复投递；
	// 邮件正文与参数里是明文凭据，作废时立刻清掉。
	if err := purgeAccountCredentialsTx(tx, userID, u.Email); err != nil {
		return nil, err
	}
	// 兑换流水与登录日志保留：它们属于审计数据，删除会让风控出现盲区。
	if err := tx.Delete(&model.User{}, userID).Error; err != nil {
		return nil, err
	}
	return ports, nil
}

// purgeAccountAfterCommit 是两条删除路径共用的善后流程。
//
// 调用时机：账号行已经随事务**提交**删除。顺序是有讲究的，每一步都对应
// 一种「账号看起来没了、实际还在生效」的状态：
//
//  1. 内存态清理：插件热路径查的是内存里的会话与准入标记，不先清的话，
//     已登录的 frpc 仍会被放行新连接——账号都删了还在跑，这是最不该出现的
//     一种状态。
//  2. 断流：账号删掉只能拦住**新**连接，frps 与 frpc 之间已经在转发的数据流
//     不经过任何准入判断，会一直跑到客户端自己退出。账号行已不存在，
//     users.state_version 无从读取，所以走「按前缀 + 实例身份尽力关闭」
//     那条路径（见 proxy_drain.go 的 CloseDeletedUserProxies）。
//     关闭失败不影响删除结果：账号已经删干净了，报错只会让管理员重试并
//     得到「用户不存在」；残留数量由该函数记日志。
//  3. 回收防火墙端口：隧道没了，宿主机上的放行规则要收回，否则会一直留着。
//     放在最后：回收失败（helper 不可达、端口受保护）不该让已经完成的删除
//     回滚；失败会记日志，由人工清理。
//
// ports 来自事务内收集的端口清单。并发建隧道的窗口已由事务开头的用户行锁
// 关掉：建隧道的事务同样要先锁用户行，本事务提交之前它插不进来；提交之后
// 它重读用户会得到「不存在」而整体失败。所以 ports 与这次 DELETE 删掉的
// 隧道是同一批，不会漏出孤儿端口。
func (s *Services) purgeAccountAfterCommit(userID uint, ports []portProto) {
	// 所有管理路径写准入标记前都递增版本号（见 Runtime.guardVer），
	// 让在途的后台刷新识别「快照已过时」并让路。
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(userID, false)
	s.Runtime.SetUserBlocked(userID, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	// 状态代次也一起清：账号已经不在了，留着只会让那张表随历史用户数增长。
	s.forgetUserStatusGen(userID)
	// 会话同样要清：数据库里的会话行已经随事务删除，但插件热路径
	// 查的是内存会话表，残留的话已登录的 frpc 仍会被放行新连接。
	s.Runtime.DropUserSessions(userID)

	s.closeUserProxiesAfterDelete(userID)
	s.closePorts(ports)
}
