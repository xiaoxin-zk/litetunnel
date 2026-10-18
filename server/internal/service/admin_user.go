package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// ListUsers 分页查询用户。
func (s *Services) ListUsers(keyword, status string, groupID uint, offset, limit int) ([]model.User, int64, error) {
	q := s.DB.Model(&model.User{})
	if keyword != "" {
		kw := "%" + keyword + "%"
		q = q.Where("username LIKE ? OR email LIKE ? OR remark LIKE ?", kw, kw, kw)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if groupID > 0 {
		q = q.Where("group_id = ?", groupID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.User
	err := q.Preload("Group").Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// AdminCreateUserInput 管理员建号入参。
type AdminCreateUserInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	GroupID  uint   `json:"group_id"`
	Remark   string `json:"remark"`
}

// AdminCreateUser 管理员创建用户。
//
// 刻意**不复用 Register**：那是公开注册入口，带着注册开关、条款勾选、
// 人机验证、邮箱域名黑白名单与每日频率限制——那些是「防陌生人滥用」的策略，
// 管理员建号是受信操作，不该受它们约束。
//
// 曾经直接调 Register 并且没传 AgreedTerms，结果是管理员建号**永远失败**，
// 报「请先阅读并同意服务条款」；即便补上这个字段，只要站点关掉了注册
// 或开了人机验证，管理员照样建不了号。
//
// 共用的是数据本身那部分（格式校验、唯一性、密码哈希、初始 API Key）。
func (s *Services) AdminCreateUser(in AdminCreateUserInput) (*model.User, error) {
	username, email, err := validateNewUser(in.Username, in.Email, in.Password)
	if err != nil {
		return nil, err
	}
	if err := s.checkUserUnique(username, email); err != nil {
		return nil, err
	}
	// 邮箱标记为「未验证」：管理员填的邮箱没有走过验证码，
	// 标成已验证会在「邮箱即身份凭证」的场景下造成误判。
	user, err := s.prepareNewUser(username, email, in.Password, "", false)
	if err != nil {
		return nil, err
	}

	// 插入用户与分组赋值必须在同一事务，并对目标分组行 FOR UPDATE
	// （锁序：用户行 → 分组行，与 Redeem / AdminSetUserGroup 一致）。
	// 原先分两步有两个问题：
	//
	//   - 分组赋值这条路径既不验证分组存在、也不锁分组行，并发删除分组
	//     时会写出一个悬空的 group_id——运行期回落默认分组，界面上
	//     却显示用户属于那个分组；
	//   - 第二步失败时接口返回错误，但用户记录已经创建了——管理员重试
	//     会撞「用户名已存在」，而且库里留下一个分组/备注都不对的半成品。
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.insertUserTx(tx, user); err != nil {
			return err
		}
		updates := map[string]any{"remark": truncate(in.Remark, 200)}
		if in.GroupID > 0 {
			var g model.Group
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&g, in.GroupID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
				}
				return err
			}
			updates["group_id"] = g.ID
		}
		res := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.LoadUser(user.ID)
}

// AdminUpdateUserInput 管理员改号入参。指针字段用于区分「未传」与「传空」。
type AdminUpdateUserInput struct {
	Email    *string `json:"email"`
	Nickname *string `json:"nickname"`
	Remark   *string `json:"remark"`
}

// AdminUpdateUser 更新用户基础信息。
func (s *Services) AdminUpdateUser(id uint, in AdminUpdateUserInput) error {
	updates := map[string]any{}
	if in.Email != nil {
		updates["email"] = strings.TrimSpace(*in.Email)
	}
	if in.Nickname != nil {
		updates["nickname"] = truncate(*in.Nickname, 64)
	}
	if in.Remark != nil {
		updates["remark"] = truncate(*in.Remark, 200)
	}
	if len(updates) == 0 {
		return ErrInvalidParam
	}
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// 可能只是值未变化，仍需确认用户存在。
		var n int64
		if err := s.DB.Model(&model.User{}).Where("id = ?", id).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
	}
	return nil
}

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

// AdminSetUserStatus 禁用/启用/封禁用户。
func (s *Services) AdminSetUserStatus(id uint, status string) error {
	switch status {
	case model.UserStatusActive, model.UserStatusDisabled, model.UserStatusBanned:
	default:
		return fmt.Errorf("%w: 不支持的用户状态", ErrInvalidParam)
	}
	// 同一用户的「数据库状态更新 + 运行时标记同步」必须成对串行化。
	//
	// 两笔相反的请求（禁用 / 启用）交错时，各自的数据库写入与内存写入
	// 可能以不同顺序完成：数据库最后落到「已启用」，内存却被较早那笔
	// 置成「已封禁」——用户看到账号正常，新连接却一直被拒。持有用户锁
	// 之后，两者只可能是先后关系，内存标记随之与数据库一致。
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	res := s.DB.Model(&model.User{}).Where("id = ?", id).Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	// 令牌只验签不查状态，因此必须主动失效缓存，让禁用立即生效。
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	if status != model.UserStatusActive {
		// 禁用/封禁走独立的标记，而不是借用超额标记。
		//
		// 借用的写法有个致命后果：超额标记会被每轮流量采集按配额重算，
		// 于是「配额没超限的禁用用户」会在下一次成功采集后被重新放行——
		// 禁用是否生效取决于采集有没有跑过，现象随机且无法复现。
		s.Runtime.BumpGuardVer()
		s.Runtime.SetUserBlocked(id, true)
		// 同时撤销其运行时会话：插件热路径命中会话后只看这两个标记，
		// 但会话本身留着也没有意义——账号都禁用了。
		s.Runtime.DropUserSessions(id)
		return nil
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetUserBlocked(id, false)

	// 重新启用时**立即**按真实配额重算，而不是等下一轮流量采集。
	//
	// 禁用期间这个标记被强制置成了 true（上一步）。启用后如果只是放着
	// 不管，就要等到下一次采集成功才会恢复；而采集依赖 frps 管理接口，
	// 它恰好不可用（或采集持续报错）时，用户会看到「账号已启用，但新建
	// 连接一律被拒」，且没有任何地方说明原因。
	// 走与配额调整相同的版本条件写：并发的配额调整若在读取后发生，
	// 这里基于旧快照算出的结果会被拒绝并重读，不会把新标记覆盖回去。
	//
	// 刷新失败时**不能**把超额标记清成 false：启用账号只是恢复登录资格，
	// 并不代表获得了额外流量。清掉标记等于给一个已超额的账号放行，
	// 直到下一轮采集成功才纠正——期间流量照跑、配额照超。保持原标记
	// 并把失败明确报给管理员（重试本操作幂等，或等采集纠正）。
	if err := s.refreshQuotaFor(id); err != nil {
		return fmt.Errorf("账号已启用，但配额标记刷新失败（沿用原有超额状态，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	return nil
}

// AdminSetUserQuota 单独设定用户的流量配额（字节）。0 表示回落到分组配额。
func (s *Services) AdminSetUserQuota(id uint, quota int64) error {
	if quota < 0 {
		return fmt.Errorf("%w: 配额不能为负数", ErrInvalidParam)
	}
	// 与禁用/启用、分组调整等「数据库更新 + 运行时标记刷新」成对的操作共用
	// 同一把用户锁：并发的配额调整或状态切换交错执行时，各自的写库与内存
	// 写入可能以不同顺序完成，导致运行时标记与数据库短暂不一致。持有用户锁
	// 之后两者只可能是先后关系（版本校验见 refreshQuotaFor）。
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	res := s.DB.Model(&model.User{}).Where("id = ?", id).Update("traffic_quota", quota)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	// 先递增版本号再刷新：让在途的旧快照（后台整表刷新、并发的另一笔
	// 配额调整）让路，随后的读取必然看到刚提交的配额。
	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

// AdminResetUserTraffic 清零用户已用流量。
//
// 必须先在采集器登记待协调标记、再清零（见 Runtime.pendingTrafficReset）：
// 清零后紧邻一轮的增量是清零前采样的旧流量，不拦的话最多一个采样周期后
// 它会重新加回用户用量——管理员看到「明明清零了又涨回来了」。
// 顺序反过来（先清零后登记）会有一个窗口：增量恰好插在两步之间落库，
// 标记拦不住它。
func (s *Services) AdminResetUserTraffic(id uint) error {
	// 「登记 + 清零写库（+ 失败撤销）」整段与采集的「快照 → 提交」互斥。
	//
	// 只让撤销拿锁还不够：采集可能已经取到**不含本用户标记**的快照，
	// 管理员随后清零写库，采集再提交那份快照里的旧增量——清零后的用量
	// 又被加回，正是这套标记要防的事。持有协调锁之后，两者只可能是
	// 先后关系：要么清零先落地（采集快照一定包含标记），要么采集先提交
	// （清零随后写绝对值 0，结果仍然正确）。
	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

	// 记下本次登记的代次：撤销只能作用于这一笔。同一用户可能有并发的
	// 另一笔清零已成功登记，按用户整体撤销会把它的标记一并作废，
	// 那一笔清零前的旧增量随后就会被加回。
	gen := s.Runtime.MarkTrafficResetPending(id)
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"traffic_used": 0,
		// 推进清零代次：采集器写增量时按它做条件更新。多副本下清零请求可能
		// 落在别的实例，进程内的标记对方看不见——代次在库里，谁都看得见。
		"traffic_reset_gen": gorm.Expr("traffic_reset_gen + 1"),
		"traffic_reset_at":  time.Now().AddDate(0, 1, 0),
	})
	if res.Error != nil {
		// 清零没写进去，登记的标记必须撤销：留着它，后续采集会错误地
		// 丢弃一轮**真实**用量。已在协调区间内，用加锁版本撤销——
		// 再取一次 resetMu 会自死锁。
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return res.Error
	}
	if res.RowsAffected == 0 {
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return ErrNotFound
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(id, false)
	return nil
}

// GroupExpiry 描述这次操作要对「分组有效期」做什么，共三态：
//
//	Set=false          → 不修改（请求里没带这个字段）
//	Set=true, Value=nil → 清除（请求里显式给了 null）
//	Set=true, Value!=nil → 设为该时刻
//
// 必须区分三态：只有「非 nil 才更新」的写法会让「清空有效期」变成空操作，
// 旧值残留后到期调度会把刚改派的用户迁回默认分组。
type GroupExpiry struct {
	Set   bool
	Value *time.Time
}

// AdminSetUserGroup 调整用户分组与到期时间。
//
// 分组的存在性检查、用户行的更新放进同一事务，并按全局锁序
// （用户行 → 分组行，与 Redeem 一致）对两张行加 FOR UPDATE：
// 只在事务外查一下分组的话，「检查通过 → 更新用户」之间分组可能被删，
// 写出一个悬空的 group_id。
func (s *Services) AdminSetUserGroup(id, groupID uint, expiry GroupExpiry) error {
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, groupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
			}
			return err
		}

		updates := map[string]any{"group_id": groupID}
		if expiry.Set {
			if expiry.Value == nil {
				// 显式清除：写成 NULL，到期调度之后就不会再把这名用户迁走。
				updates["group_expire_at"] = nil
			} else {
				updates["group_expire_at"] = *expiry.Value
			}
		}
		res := tx.Model(&model.User{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		// 用户不存在时必须报错。不看 RowsAffected 的话，改一个不存在的
		// 用户会「成功」返回，管理员以为改好了，实际什么都没发生。
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		// 分组变化后刷新该用户所有隧道的限速快照。
		return tx.Model(&model.Tunnel{}).Where("user_id = ?", id).
			Update("bandwidth_limit", g.BandwidthLimit).Error
	})
	if err != nil {
		return err
	}

	// 配额刷新必须放在事务**提交之后**。
	//
	// 它内部要用主连接重新查一次用户，而 SQLite 默认只开一个连接
	// （store.go 里 SetMaxOpenConns(1)）：事务占着那唯一的连接时，
	// 这次查询永远等不到它释放，而事务又在等查询返回——整个请求就卡死在
	// 那里。管理后台的表现是「点一下没反应」，日志里什么都没有。
	//
	// 同样先递增版本号：改组会改变生效配额，在途的旧快照必须让路。
	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

// AdminResetUserPassword 重置用户密码。
//
// 同时自增令牌版本，把该用户所有已登录会话踢下线。
func (s *Services) AdminResetUserPassword(id uint, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁用户行：改密与「重置邮件送达后激活」都以这一行为序。
		var locked model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&locked, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		res := tx.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		// 已建立的客户端会话同步置为离线：token_version 只影响网页 JWT，
		// frpc 用的是 client_secret，不会因此失效。
		if err := revokeClientSessionsTx(tx, id); err != nil {
			return err
		}
		// 旧的重置链接与排队中的重置邮件一并作废：改密之后它们不该还能用。
		return revokePasswordResetTx(tx, id, locked.Email)
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	// 内存会话必须一起清：插件热路径只查内存，命中后只校验配额就放行。
	// 管理员重置密码的典型场景是「账号可能已被他人控制」，留着会话等于没重置。
	s.Runtime.DropUserSessions(id)
	return nil
}

// AdminResetUserSecret 重置客户端接入凭据，旧客户端立即失效。
func (s *Services) AdminResetUserSecret(id uint) (string, error) {
	u, err := s.LoadUser(id)
	if err != nil {
		return "", err
	}
	return s.ResetClientSecret(u)
}

// refreshQuotaFor 刷新单个用户的超额标记。
//
// 读库与写标记之间存在窗口：并发的两笔配额调整，先发起的那笔可能读到
// 旧配额、却后完成写入，用旧结果覆盖新标记（用户被错误放行或被错误
// 拦截）。因此版本号在**读库之前**取，写入用 SetQuotaExceededIfVer
// 条件写；版本变了就说明期间有别的管理操作（或后台刷新）动过，重读重试。
//
// 调用方必须在**自己的数据库写入提交之后**先 BumpGuardVer，再调用本方法：
// 递增让在途的旧快照让路，之后的读取必然看到刚提交的新状态。
//
// 读取失败必须返回错误：标记留在旧值上（比如「超额」），调用方若把它
// 当成功上报，管理员会以为调整已生效，而插件还在按旧标记拦截——
// 「改了配额却没反应」且无处排查。
func (s *Services) refreshQuotaFor(id uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		u, err := s.LoadUser(id)
		if err != nil {
			return fmt.Errorf("刷新配额标记失败（用户 %d）: %w", id, err)
		}
		exceeded := s.QuotaExceeded(u)
		if s.Runtime.SetQuotaExceededIfVer(u.ID, exceeded, ver) {
			return nil
		}
		// 版本在读取期间被推进：这次算出的结果基于旧快照，丢弃重读。
	}
	return fmt.Errorf("刷新配额标记失败（用户 %d）：并发调整过于频繁，未能稳定写入", id)
}

// ---- 分组管理 ----

// ListGroups 全部分组。
func (s *Services) ListGroups() ([]model.Group, error) {
	var list []model.Group
	err := s.DB.Order("priority desc, id asc").Find(&list).Error
	return list, err
}

// GroupInput 分组入参。
type GroupInput struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	MaxTunnels          int    `json:"max_tunnels"`
	MaxPorts            int    `json:"max_ports"`
	TrafficQuota        int64  `json:"traffic_quota"`
	BandwidthLimit      int64  `json:"bandwidth_limit"`
	AllowProtocols      string `json:"allow_protocols"`
	AllowCustomDomain   bool   `json:"allow_custom_domain"`
	AllowPrivilegedPort bool   `json:"allow_privileged_port"`
	Priority            int    `json:"priority"`
}

func (in *GroupInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 32 {
		return fmt.Errorf("%w: 分组名称需为 1-32 个字符", ErrInvalidParam)
	}
	if in.MaxTunnels < 0 || in.MaxPorts < 0 || in.TrafficQuota < 0 || in.BandwidthLimit < 0 {
		return fmt.Errorf("%w: 数值不能为负数", ErrInvalidParam)
	}
	// 协议白名单只接受已知取值，防止脏数据流入插件校验逻辑。
	allowed := map[string]bool{"tcp": true, "udp": true, "http": true, "https": true}
	parts := strings.Split(strings.ToLower(in.AllowProtocols), ",")
	cleaned := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !allowed[p] {
			return fmt.Errorf("%w: 不支持的协议 %q", ErrInvalidParam, p)
		}
		if !seen[p] {
			seen[p] = true
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("%w: 至少需要允许一种协议", ErrInvalidParam)
	}
	in.AllowProtocols = strings.Join(cleaned, ",")
	return nil
}

// CreateGroup 新建分组。
func (s *Services) CreateGroup(in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	g := &model.Group{
		Name:                in.Name,
		Description:         truncate(in.Description, 200),
		MaxTunnels:          in.MaxTunnels,
		MaxPorts:            in.MaxPorts,
		TrafficQuota:        in.TrafficQuota,
		BandwidthLimit:      in.BandwidthLimit,
		AllowProtocols:      in.AllowProtocols,
		AllowCustomDomain:   in.AllowCustomDomain,
		AllowPrivilegedPort: in.AllowPrivilegedPort,
		Priority:            in.Priority,
	}
	if err := s.DB.Create(g).Error; err != nil {
		return nil, fmt.Errorf("分组名称可能已存在: %w", err)
	}
	return g, nil
}

// UpdateGroup 更新分组，并同步刷新该组所有用户的隧道限速快照。
func (s *Services) UpdateGroup(id uint, in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var g model.Group
	if err := s.DB.First(&g, id).Error; err != nil {
		return nil, ErrNotFound
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{
			"name":                  in.Name,
			"description":           truncate(in.Description, 200),
			"max_tunnels":           in.MaxTunnels,
			"max_ports":             in.MaxPorts,
			"traffic_quota":         in.TrafficQuota,
			"bandwidth_limit":       in.BandwidthLimit,
			"allow_protocols":       in.AllowProtocols,
			"allow_custom_domain":   in.AllowCustomDomain,
			"allow_privileged_port": in.AllowPrivilegedPort,
			"priority":              in.Priority,
		}
		if err := tx.Model(&model.Group{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Model(&model.Tunnel{}).
			Where("user_id IN (?)", tx.Model(&model.User{}).Select("id").Where("group_id = ?", id)).
			Update("bandwidth_limit", in.BandwidthLimit).Error
	})
	if err != nil {
		return nil, err
	}
	if err := s.DB.First(&g, id).Error; err != nil {
		return nil, err
	}

	// 事务提交后刷新该组用户的超额标记。
	//
	// 配额可能被调低（原本没超额的变成超额）或调高（原本超额的可以放行了），
	// 而 Runtime.exceeded 是插件实时拦截的依据。不刷新的话要等下一轮成功
	// 采集才生效——frps 管理接口恰好不可用时，这个标记会一直停在旧值上：
	// 调低配额后用户还能继续建连接，调高配额后用户仍然被拒。
	//
	// 刷新失败要如实返回：分组本身已更新，但整组标记还停在旧值——
	// 把它报成成功，管理员不会知道「调低配额后用户仍能建连接」。
	// 错误信息里点明这一点，管理员重试即可（更新幂等）。
	//
	// 先递增版本号：让在途的旧快照让路，随后的整组读取看到刚提交的新配额。
	s.Runtime.BumpGuardVer()
	if err := s.refreshQuotaForGroup(id); err != nil {
		return &g, fmt.Errorf("分组已更新，但配额标记刷新失败（本组用户将沿用旧标记，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	return &g, nil
}

// refreshQuotaForGroup 刷新某分组下所有用户的超额标记。
//
// 一次查询取出该组全部用户（带分组），而不是逐个 LoadUser：
// 一个分组可能有成百上千个用户，逐个查会把一次管理操作变成一串查询。
//
// 与 refreshQuotaFor 同样的版本协调：版本号在读库之前取，逐个条件写；
// 中途版本被推进（另一笔管理操作/后台刷新）就整组重读重试——否则
// 先发起的旧快照会用旧配额覆盖后完成的新标记。调用方必须已在自己
// 的数据库写入提交之后 BumpGuardVer。
func (s *Services) refreshQuotaForGroup(groupID uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		var users []model.User
		if err := s.DB.Preload("Group").Where("group_id = ?", groupID).Find(&users).Error; err != nil {
			// 读取失败必须返回错误：整组标记都停在旧值，调用方不能把这次
			// 操作当成功上报（见 refreshQuotaFor 的说明）。
			return fmt.Errorf("刷新分组 %d 的配额标记失败: %w", groupID, err)
		}
		stable := true
		for i := range users {
			s.EnsureTrafficPeriod(&users[i])
			if !s.Runtime.SetQuotaExceededIfVer(users[i].ID, s.QuotaExceeded(&users[i]), ver) {
				// 版本已推进：本组这一轮的结果基于旧快照，剩下的人
				// 不再写，整组重来（否则同一组里会出现新旧混杂）。
				stable = false
				break
			}
		}
		if stable {
			return nil
		}
	}
	return fmt.Errorf("刷新分组 %d 的配额标记失败：并发调整过于频繁，未能稳定写入", groupID)
}

// DeleteGroup 删除分组。默认分组、仍被占用的分组、仍有未核销升级码的分组
// 不允许删除。
//
// 检查未核销兑换码的原因：GenerateCodes 允许生成指向任意现存分组的升级码，
// 而分组一删，这些码就成了废纸——兑换时按 group_id 找不到分组，
// 返回「兑换码无效」，用户拿着一张永远用不掉的码。管理员删分组时
// 看不到这层关联，必须由这里拦下来：先停用/删除这些码，或迁移到别的分组。
//
// 检查与删除放进同一事务：分开的话，「检查通过 → 删除」之间仍可能插进
// 一次兑换（见 Redeem 里对分组行的 FOR UPDATE），事务至少保证
// 这两个步骤看到的是同一个数据库状态。
func (s *Services) DeleteGroup(id uint) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// FOR UPDATE 锁住分组行：GenerateCodes 与 AdminSetUserGroup 对
		// 同一行加锁（见 Redeem 里的全局锁序说明）。不锁的话，
		// 生成一批升级码或分配用户可以插进「计数检查 → 删除」之间，
		// 检查看到的是旧快照，删掉的分组背后已经挂上了新引用。
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if g.IsDefault {
			return fmt.Errorf("%w: 默认分组不允许删除", ErrInvalidParam)
		}
		var used int64
		if err := tx.Model(&model.User{}).Where("group_id = ?", id).Count(&used).Error; err != nil {
			return err
		}
		if used > 0 {
			return fmt.Errorf("%w: 仍有 %d 个用户属于该分组，请先迁移", ErrInvalidParam, used)
		}
		// 只看未核销的：已用尽/已停用的码本来就不能再兑换，
		// 指向已删除分组对它们没有影响。
		var pending int64
		if err := tx.Model(&model.RedeemCode{}).
			Where("group_id = ? AND status = ?", id, model.RedeemStatusUnused).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return fmt.Errorf("%w: 还有 %d 张指向该分组的未核销升级码，请先停用或删除它们",
				ErrInvalidParam, pending)
		}
		res := tx.Delete(&model.Group{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ---- 隧道管理（管理侧）----
