package service

import (
	"context"
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
//
// 整组变更走 updateProfileLocked：邮箱、昵称、备注必须在同一个用户锁与同一个
// 事务里落库。以前邮箱先单独提交、其余字段后提交，后一步失败时接口返回失败，
// 而邮箱（连同 token_version 递增、旧地址恢复凭据作废）已经生效——管理员看到
// 一次失败，实际上账号已经被改了一半。
func (s *Services) AdminUpdateUser(id uint, in AdminUpdateUserInput) error {
	fields := map[string]any{}
	var email *string
	if in.Email != nil {
		e := strings.ToLower(strings.TrimSpace(*in.Email))
		if e != "" && !IsValidEmail(e) {
			return fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		// 管理员直接填的地址没走过验证码，email_verified 由落库处置 false。
		email = &e
	}
	if in.Nickname != nil {
		fields["nickname"] = truncate(*in.Nickname, 64)
	}
	if in.Remark != nil {
		fields["remark"] = truncate(*in.Remark, 200)
	}
	if len(fields) == 0 && email == nil {
		return ErrInvalidParam
	}
	_, err := s.updateProfileLocked(id, profilePatch{
		email: email,
		// 邮箱是找回密码的入口：管理员改过之后，既有的网页会话必须失效。
		bumpTokenVersion: true,
		fields:           fields,
	})
	return err
}

// userStatusEntry 是一个用户的状态代次记录。
type userStatusEntry struct {
	gen uint64
	at  time.Time
}

const (
	// statusGenMaxEntries 是代次表的容量上限。正常站点远达不到
	// （每个改过状态的用户一项），触顶说明账号在被大量创建/删除。
	statusGenMaxEntries = 100000
	// statusGenTTL 是代次记录的保留期：超过这么久没改过状态的条目可以回收。
	statusGenTTL = 7 * 24 * time.Hour
)

// bumpUserStatusGen 递增并返回该用户的状态代次。
//
// 调用时机必须在「状态已写入数据库」之后、释放用户锁之前：它标记的是
// 「第几次状态生效」，跨锁的后续动作拿它当自己是否过期的凭据。
func (s *Services) bumpUserStatusGen(userID uint) uint64 {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	e := s.statusGens[userID]
	e.gen++
	e.at = time.Now()
	s.statusGens[userID] = e
	if len(s.statusGens) > statusGenMaxEntries {
		s.sweepStatusGensLocked(e.at)
	}
	return e.gen
}

// setUserStatusGen 用落库的状态版本覆盖内存代次。
//
// 内存这份只用于同实例的快速判断；跨实例的判据必须查库
// （见 userStateVersionFromDB）。两者值域一致，都是 users.state_version。
func (s *Services) setUserStatusGen(userID uint, gen uint64) {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	s.statusGens[userID] = userStatusEntry{gen: gen, at: time.Now()}
	if len(s.statusGens) > statusGenMaxEntries {
		s.sweepStatusGensLocked(time.Now())
	}
}

// userStateVersionFromDB 读取账号状态版本。
//
// 返回 ErrRecordNotFound 表示账号已不存在（此时「谁先谁后」已无意义，
// 调用方不应据此放弃断流）。其它错误表示数据库暂时不可用，同样不构成
// 「状态已变」的证据。
func (s *Services) userStateVersionFromDB(userID uint) (uint64, error) {
	var u model.User
	if err := s.DB.Select("id", "state_version").First(&u, userID).Error; err != nil {
		return 0, err
	}
	return u.StateVersion, nil
}

// userStatusGen 返回该用户当前的状态代次；从未改过状态时为 0。
func (s *Services) userStatusGen(userID uint) uint64 {
	s.statusGenMu.Lock()
	defer s.statusGenMu.Unlock()
	return s.statusGens[userID].gen
}

// forgetUserStatusGen 在账号删除后清掉代次记录。
//
// 删除之后不会再有任何断流任务拿这个 ID 当判据（主键不复用），留着只是
// 让表随历史用户数增长。
func (s *Services) forgetUserStatusGen(userID uint) {
	s.statusGenMu.Lock()
	delete(s.statusGens, userID)
	s.statusGenMu.Unlock()
}

// sweepStatusGensLocked 回收代次表。调用方必须持有 statusGenMu。
//
// 先按保留期清，仍超上限就按遍历顺序删到一半：这里不排序（10 万条排序
// 在锁内会把所有登录/管理操作拖出长尾），遍历顺序本身是伪随机的。
// 极端情况下丢掉一条仍在进行中的断流的判据，代价是它可能多关几条刚建的
// 代理；相比内存随历史用户数无限增长，这是更小的故障。
func (s *Services) sweepStatusGensLocked(now time.Time) {
	cutoff := now.Add(-statusGenTTL)
	for id, e := range s.statusGens {
		if e.at.Before(cutoff) {
			delete(s.statusGens, id)
		}
	}
	if len(s.statusGens) <= statusGenMaxEntries {
		return
	}
	target := statusGenMaxEntries / 2
	for id := range s.statusGens {
		if len(s.statusGens) <= target {
			break
		}
		delete(s.statusGens, id)
	}
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

	// 状态与状态版本必须一起落库：断流任务跨锁、跨实例执行，只靠进程内
	// 代次的话，实例 B 上的重新启用不会被实例 A 的断流看到。
	var gen uint64
	var drainIntent string
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.User{}).Where("id = ?", id).
			Updates(map[string]any{
				"status":        status,
				"state_version": gorm.Expr("state_version + 1"),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if status != model.UserStatusActive {
			// 把数据库里的会话置为离线，**必须和状态写在同一个事务里**。
			//
			// 为什么不能等事务提交之后再撤销：提交点就是其他实例看到「账号已
			// 禁用」的唯一时刻。提交后到撤销语句之间的那一小段里，别的实例上
			// 的插件回调（onNewUserConn → EnsureSessionOnline →
			// FindTrustedClientSession）读到的仍是 online=true、没过期的会话，
			// 于是继续放行新连接——账号明明已被禁用，却还在新建数据连接。
			// 更糟的是撤销语句若失败，这个窗口会一直存在到那台实例上的会话
			// 过期为止（sessionTrustWindow 10 分钟），而本实例的日志只有一行。
			//
			// 放进事务还有一个副作用是想要的：撤销失败会让整笔状态变更回滚，
			// 管理员收到错误而不是「已禁用」——不会出现「库里禁用、库里会话
			// 仍在线」这种自相矛盾的状态。
			//
			// 已有的「事务外 CloseUserProxies 带 15s 超时」保持不变：那个要访问
			// frps，不能拖进事务；这里只做一次 UPDATE。
			if err := revokeClientSessionsTx(tx, id); err != nil {
				return err
			}
		}
		// 读回本次写入的版本：后面那段断流要放掉用户锁去做（可能十几秒），
		// 这期间若账号被重新启用（任何实例上），版本变化就是「本次断流
		// 已过期」的信号。
		var u model.User
		if err := tx.Select("state_version").First(&u, id).Error; err != nil {
			return err
		}
		gen = u.StateVersion
		if status != model.UserStatusActive {
			// 断流意图与禁用状态必须在同一事务提交：进程若在提交后、
			// CloseUserProxies 前退出，后台仍能靠这条记录继续断流。
			drainIntent = s.recordProxyDrainPendingDB(tx, proxyDrainRequest{
				userID: id,
				prefix: FrpUserOf(id) + ".",
				gen:    gen,
			})
			if drainIntent == "" {
				return errors.New("记录账号禁用断流意图失败")
			}
		}
		return nil
	})
	if err != nil {
		lock.Unlock()
		return err
	}
	// 内存代次跟随落库版本，供同实例的快速判断（见 CloseUserProxies）。
	s.setUserStatusGen(id, gen)
	// 令牌只验签不查状态，因此必须主动失效缓存，让禁用立即生效。
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
	if status != model.UserStatusActive {
		// 时间点必须取在事务提交成功之后：锁等待期间可能已经有代理启动，
		// 不能把它们误判成「禁用后启动」而跳过断流。
		disabledAt := time.Now()
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
		// 「改库 + 置阻断标记」到此完成，释放用户锁再做断流：断流要访问
		// frps 管理接口、最长 15 秒，持锁会让同一账号的其它管理操作
		// （改配额、改分组、删除）全部排队 15 秒。
		lock.Unlock()

		// 主动关闭该用户在 frps 侧已建立的代理：只清会话拦得住新连接，
		// 拦不住已经建立的代理流。逐个关闭，实现「立即断流」。
		// 用带超时的上下文，避免 frps 管理接口不可用时把禁用操作卡死。
		//
		// 超时/失败不是终点：CloseUserProxies 在动手之前先把这次断流意图写进
		// 待办表（见 proxy_drain_retry.go），没关掉的代理由后台重试器按退避
		// 继续关。所以这里不需要（也不能）等它成功——禁用必须立刻生效，
		// 而「关流量」是个可以慢慢补偿的外部动作。
		closeCtx, cancel := context.WithTimeout(context.Background(), closeProxiesTimeout)
		s.closeUserProxiesWithIntent(closeCtx, id, gen, disabledAt, drainIntent)
		cancel()
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
		lock.Unlock()
		return fmt.Errorf("账号已启用，但配额标记刷新失败（沿用原有超额状态，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	lock.Unlock()
	return nil
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
