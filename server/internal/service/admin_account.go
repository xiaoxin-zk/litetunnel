package service

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 管理员账号管理：账号的增删改查、角色与状态变更、最后超级管理员保护。

// LoadAdmin 载入管理员。
func (s *Services) LoadAdmin(id uint) (*model.Admin, error) {
	var a model.Admin
	if err := s.DB.First(&a, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// AdminProfileInput 管理员自助修改资料的入参。
// 使用指针以区分「未提交该字段」与「提交了空值」。
type AdminProfileInput struct {
	Username *string `json:"username"`
	Nickname *string `json:"nickname"`
}

// AdminUpdateProfile 管理员修改自己的登录账号与昵称。
//
// 允许改登录账号是刻意的：初始账号名来自 .env（默认 admin），
// 是公开可猜的。攻击者据此可以对管理员账号做定向爆破或定向锁定。
// 允许改成不可预测的名字，能显著降低这类定向攻击的性价比。
//
// 改名不使当前令牌失效（版本号未变）：否则管理员每次改名都要重新登录，
// 而账号名本身不是密钥，改名也不意味着凭据泄露。
func (s *Services) AdminUpdateProfile(id uint, in AdminProfileInput) (*model.Admin, error) {
	var result model.Admin
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 资料修改与改密/改角色/双因素同用 adminMu，并在事务内 FOR UPDATE
		// 重读目标行：事务外读到的快照在并发下可能已经过时（例如并发改名
		// 已经把登录账号占掉），用旧快照做唯一性判断会漏判，返回对象也会过期。
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		updates := map[string]any{}
		if in.Username != nil {
			name := strings.TrimSpace(*in.Username)
			if name != a.Username {
				if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
					return fmt.Errorf("%w: 登录账号需为 3-32 位字母、数字或下划线", ErrInvalidParam)
				}
				var n int64
				if err := tx.Model(&model.Admin{}).Where("username = ? AND id <> ?", name, id).Count(&n).Error; err != nil {
					return err
				}
				if n > 0 {
					return ErrUsernameTaken
				}
				updates["username"] = name
			}
		}
		if in.Nickname != nil {
			nick := strings.TrimSpace(*in.Nickname)
			if len([]rune(nick)) > 32 {
				return fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
			}
			updates["nickname"] = nick
		}

		if len(updates) == 0 {
			result = a
			return nil
		}
		res := tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			// 并发改名撞唯一索引，同样按占用处理。
			return ErrUsernameTaken
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return tx.First(&result, id).Error
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListAdmins 列出全部管理员账号，供后台自查是否残留无用账号。
func (s *Services) ListAdmins() ([]model.Admin, error) {
	var list []model.Admin
	err := s.DB.Order("id asc").Find(&list).Error
	return list, err
}

// ---- 管理员账号管理 ----

// 合法角色集合。
var validAdminRoles = map[string]bool{
	"super":    true, // 全部权限
	"operator": true, // 可写，不可管理管理员
	"auditor":  true, // 只读
}

// AdminCreateInput 新建管理员入参。
type AdminCreateInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
}

// CreateAdmin 新建管理员账号。
func (s *Services) CreateAdmin(in AdminCreateInput) (*model.Admin, error) {
	in.Username = strings.TrimSpace(in.Username)
	if len(in.Username) < 3 || len(in.Username) > 32 || !isSafeName(in.Username) {
		return nil, fmt.Errorf("%w: 账号需为 3-32 位字母、数字或下划线", ErrInvalidParam)
	}
	if len(in.Password) < 12 {
		return nil, fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
	}
	if in.Role == "" {
		in.Role = "operator"
	}
	if !validAdminRoles[in.Role] {
		return nil, fmt.Errorf("%w: 不支持的角色 %q", ErrInvalidParam, in.Role)
	}

	var n int64
	if err := s.DB.Model(&model.Admin{}).Where("username = ?", in.Username).Count(&n).Error; err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrUsernameTaken
	}

	hashed, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	nickname := strings.TrimSpace(in.Nickname)
	if nickname == "" {
		nickname = in.Username
	}
	a := &model.Admin{
		Username:     in.Username,
		Password:     hashed,
		Nickname:     truncate(nickname, 64),
		Role:         in.Role,
		Status:       "active",
		TokenVersion: 1,
	}
	if err := s.DB.Create(a).Error; err != nil {
		return nil, ErrUsernameTaken
	}
	return a, nil
}

// AdminUpdateInput 修改管理员入参。指针用于区分「未传」与「传空」。
type AdminUpdateInput struct {
	Nickname *string `json:"nickname"`
	Role     *string `json:"role"`
	Status   *string `json:"status"`
}

// UpdateAdmin 修改管理员资料。为避免把自己锁在门外，
// 不允许修改自己的角色与状态。
func (s *Services) UpdateAdmin(id, operatorID uint, in AdminUpdateInput) error {
	target, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}

	updates := map[string]any{}
	if in.Nickname != nil {
		updates["nickname"] = truncate(strings.TrimSpace(*in.Nickname), 64)
	}

	roleChanged := in.Role != nil && *in.Role != target.Role
	statusChanged := in.Status != nil && *in.Status != target.Status

	if in.Role != nil || in.Status != nil {
		if id == operatorID {
			return fmt.Errorf("%w: 不能修改自己的角色或状态", ErrInvalidParam)
		}
		if in.Role != nil {
			if !validAdminRoles[*in.Role] {
				return fmt.Errorf("%w: 不支持的角色 %q", ErrInvalidParam, *in.Role)
			}
			// 不允许把最后一个超级管理员降级。
			if target.Role == "super" && *in.Role != "super" {
				if err := s.assertNotLastSuperAdmin(id, "降级"); err != nil {
					return err
				}
			}
			updates["role"] = *in.Role
		}
		if in.Status != nil {
			if *in.Status != "active" && *in.Status != "disabled" {
				return fmt.Errorf("%w: 不支持的账号状态", ErrInvalidParam)
			}
			if *in.Status != "active" && target.Role == "super" {
				if err := s.assertNotLastSuperAdmin(id, "禁用"); err != nil {
					return err
				}
			}
			updates["status"] = *in.Status
		}
	}

	// 角色或状态真的变了，就必须让已签发的令牌立即失效。
	//
	// 只清身份缓存是不够的：AdminAuth 的授权读的是**令牌里的角色**
	// （claims.Role），缓存只影响「账号是否启用 / 令牌版本是否一致」这两项。
	// 不动版本号的话，被降级的超级管理员手里那枚旧令牌在过期前依然能走
	// super 路由——降级形同没做。
	//
	// 只在值真的变化时递增：把角色重复设置成同一个值也踢人下线，
	// 会让管理员在无意义的操作里被莫名登出。
	if roleChanged || statusChanged {
		updates["token_version"] = gorm.Expr("token_version + 1")
	}

	if len(updates) == 0 {
		return nil
	}
	// 真正的守卫在 applyAdminUpdate 里：上面那次数量检查只负责给出准确的报错，
	// 并发下它可能已经过时。
	if err := s.applyAdminUpdate(id, updates); err != nil {
		return err
	}
	// 角色或状态变更后，让该账号的旧令牌立即失效。
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// applyAdminUpdate 在串行化保护内应用管理员变更。
//
// 「系统里至少留一个可用的超级管理员」不能只靠变更前的一次 count：两名超级
// 管理员并发互相降级时，两个请求都会读到「还有对方在」，于是双双通过检查，
// 最终一个可用的超级管理员都不剩——而这是**谁都无法再登录后台**的死锁，
// 只能改数据库才能恢复。
//
// 所以这里做三件事：
//  1. 进程内互斥：控制面是单进程，这组操作因此串行；
//  2. 检查与 UPDATE 放进同一个事务，对其它写路径原子；
//  3. 检查用 tx 而不是主连接——SQLite 默认只开一条连接，在事务里用主连接
//     重新查询会永久等它释放（AdminSetUserGroup 就踩过这个自锁）。
func (s *Services) applyAdminUpdate(id uint, updates map[string]any) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 在事务内重读目标行：调用方传入的是事务外读的旧快照，并发
		// 降权/禁用/删除可能已经改掉它的 role/status。锁住这行再复核，
		// 否则「最后超管」的判断会基于过期状态，可能被并发操作绕过。
		var fresh model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fresh, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if err := assertSuperAdminRemainsAfterUpdate(tx, &fresh, updates); err != nil {
			return err
		}
		return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error
	})
}

// assertSuperAdminRemainsAfterUpdate 复核「改完之后系统里还有可用的超级管理员」。
//
// 只有「本来是启用的超级管理员、改完不是了」才需要复核；改昵称、把别人升成
// 超级管理员都不可能减少可用超级管理员的数量。
func assertSuperAdminRemainsAfterUpdate(tx *gorm.DB, target *model.Admin, updates map[string]any) error {
	if target.Role != "super" || target.Status != "active" {
		return nil
	}
	role, status := target.Role, target.Status
	if v, ok := updates["role"].(string); ok {
		role = v
	}
	if v, ok := updates["status"].(string); ok {
		status = v
	}
	if role == "super" && status == "active" {
		return nil
	}
	return assertNotLastSuperAdminIn(tx, target.ID, "降级或禁用")
}

// DeleteAdmin 删除管理员。不允许删除自己，也不允许删除最后一个超级管理员。
//
// 「最后一个」的判断与删除本身必须原子：只是「先查后删」的话，两名超级管理员
// 并发互相删除会双双通过检查，最终谁都不剩。
func (s *Services) DeleteAdmin(id, operatorID uint) error {
	if id == operatorID {
		return fmt.Errorf("%w: 不能删除当前登录的账号", ErrInvalidParam)
	}
	target, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	// 快速检查，负责给出准确的报错文案；权威判断在下面的临界区里。
	if target.Role == "super" {
		if err := s.assertNotLastSuperAdmin(id, "删除"); err != nil {
			return err
		}
	}

	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 在事务内重读目标行：target 是事务外读的旧快照，其 role 可能在
		// 这之间被并发改动（升/降级）。用旧角色决定要不要做超管保护，
		// 会漏拦「并发升成超管后被删」这种本应受保护的情况。
		var fresh model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fresh, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if fresh.Role == "super" {
			if err := assertNotLastSuperAdminIn(tx, fresh.ID, "删除"); err != nil {
				return err
			}
		}
		return tx.Delete(&model.Admin{}, fresh.ID).Error
	}); err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// AdminSetPassword 管理员重置他人的登录密码。
func (s *Services) AdminSetPassword(id uint, newPassword string) error {
	if len(newPassword) < 12 {
		return fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// 与改密/删号/改角色同用管理员锁，并在事务内重读确认目标仍存在：
	// 并发删除时若先删后改，这里会明确报错而非静默成功。
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
		}).Error
	})
	if err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// assertNotLastSuperAdmin 确保系统里始终至少保留一个可用的超级管理员，
// 否则会出现「谁都进不去后台」的死锁。
//
// 这一份走主连接，只用于变更前的快速检查（给出准确的报错文案）。
// 权威判断在 applyAdminUpdate / DeleteAdmin 的事务里用 tx 重新数一次——
// 变更前这次 count 在并发下可能已经过时。
func (s *Services) assertNotLastSuperAdmin(excludeID uint, action string) error {
	return assertNotLastSuperAdminIn(s.DB, excludeID, action)
}

// assertNotLastSuperAdminIn 在给定的连接或事务上统计剩余可用超级管理员。
//
// 必须能接受 tx：SQLite 默认只开一条连接，在事务里用主连接重新查询会永久
// 等它释放（AdminSetUserGroup 就踩过这个自锁）。
func assertNotLastSuperAdminIn(db *gorm.DB, excludeID uint, action string) error {
	var n int64
	if err := db.Model(&model.Admin{}).
		Where("role = ? AND status = ? AND id <> ?", "super", "active", excludeID).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: 系统必须保留至少一个启用的超级管理员，无法%s该账号", ErrInvalidParam, action)
	}
	return nil
}
