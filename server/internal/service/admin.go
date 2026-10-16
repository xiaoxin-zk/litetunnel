package service

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// AdminAuthenticate 校验管理员凭据（含可选的动态口令）。
//
// 与用户登录完全分离：不同的表、不同的入口、不同的令牌域。
//
// 管理后台与用户控制台共用公网端口，因此口令之外还要求第二因素：
// 已启用 TOTP 的账号必须提交正确的动态口令才能换取令牌。
func (s *Services) AdminAuthenticate(username, password, totpCode, ip string) (*model.Admin, error) {
	username = strings.TrimSpace(username)
	var a model.Admin
	err := s.DB.Where("username = ?", username).First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 即使用户不存在也执行一次哈希校验，抹平响应时间差异，避免账号枚举。
		auth.VerifyPassword("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin", password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if !auth.VerifyPassword(a.Password, password) {
		return nil, ErrBadCredentials
	}
	if a.Status != "active" {
		return nil, ErrAccountDisabled
	}

	if a.TOTPEnabled {
		if strings.TrimSpace(totpCode) == "" {
			return nil, ErrTOTPRequired
		}
		step, ok := auth.VerifyTOTPStep(a.TOTPSecret, totpCode, time.Now())
		if !ok {
			return nil, ErrTOTPInvalid
		}
		// 登记这一步已用过：同一口令在有效窗口内（±1 步，最长 90 秒）
		// 只能成功一次。这是阻止「钓鱼反代拿到口令后立刻重放」的关键一环。
		//
		// 判定走数据库（原子条件更新），因此重启、多实例都不会丢记录。
		if !s.ClaimTOTPStep(a.ID, step) {
			return nil, ErrTOTPReplay
		}
		now := time.Now()
		_ = s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
			Update("totp_verified_at", now).Error
		a.TOTPVerifiedAt = &now
	}

	now := time.Now()
	_ = s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
		Updates(map[string]any{"last_login_at": now, "last_login_ip": ip}).Error
	a.LastLoginAt = &now
	a.LastLoginIP = ip
	return &a, nil
}

// ---- 双因素认证 ----

// AdminTOTPSetup 生成新的 TOTP 密钥，此时尚未启用。
//
// 两步式设计（先生成、再用一次正确口令确认）是为了避免用户扫码失败后
// 就把自己锁在门外。
func (s *Services) AdminTOTPSetup(id uint) (secret, otpauthURL string, err error) {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return "", "", err
	}
	secret, err = auth.GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"totp_secret":  secret,
		"totp_enabled": false,
		// 换了一把密钥，旧的水位线对新密钥没有意义：不清掉的话，
		// 在同一时间窗口内重新绑定会被判成「重放」而失败。
		"totp_last_step": 0,
	}).Error; err != nil {
		return "", "", err
	}
	return secret, auth.OtpauthURL("LiteTunnel", a.Username, secret), nil
}

// AdminTOTPEnable 用一次正确的动态口令确认绑定并启用双因素认证。
func (s *Services) AdminTOTPEnable(id uint, code string) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if a.TOTPSecret == "" {
		return fmt.Errorf("%w: 请先生成密钥", ErrInvalidParam)
	}
	step, ok := auth.VerifyTOTPStep(a.TOTPSecret, code, time.Now())
	if !ok {
		return ErrTOTPInvalid
	}
	// 绑定用的口令同样登记。不登记的话，「刚绑定完立刻拿同一个口令去登录」
	// 就成了一条绕过防重放的现成路径。
	if !s.ClaimTOTPStep(a.ID, step) {
		return ErrTOTPReplay
	}
	now := time.Now()
	return s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"totp_enabled":     true,
		"totp_verified_at": now,
	}).Error
}

// AdminTOTPDisable 关闭双因素认证。
//
// 关闭是降级安全等级的操作，必须重新验证登录口令，
// 避免令牌被盗后攻击者直接关掉第二因素。
func (s *Services) AdminTOTPDisable(id uint, password string) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(a.Password, password) {
		return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
	}
	return s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"totp_enabled": false,
		"totp_secret":  "",
	}).Error
}

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

// AdminChangePassword 管理员修改自己的登录密码。
//
// 管理员口令是平台的最高权限入口，因此策略比普通用户更严格：
// 长度不少于 12 位，且不允许与原密码相同。
func (s *Services) AdminChangePassword(id uint, oldPassword, newPassword string) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(a.Password, oldPassword) {
		return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
	}
	if len(newPassword) < 12 {
		return fmt.Errorf("%w: 管理员密码长度不得少于 12 位", ErrInvalidParam)
	}
	if newPassword == oldPassword {
		return fmt.Errorf("%w: 新密码不能与原密码相同", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	res := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
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
	a, err := s.LoadAdmin(id)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}

	if in.Username != nil {
		name := strings.TrimSpace(*in.Username)
		if name != a.Username {
			if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
				return nil, fmt.Errorf("%w: 登录账号需为 3-32 位字母、数字或下划线", ErrInvalidParam)
			}
			var n int64
			if err := s.DB.Model(&model.Admin{}).Where("username = ?", name).Count(&n).Error; err != nil {
				return nil, err
			}
			if n > 0 {
				return nil, ErrUsernameTaken
			}
			updates["username"] = name
		}
	}

	if in.Nickname != nil {
		nick := strings.TrimSpace(*in.Nickname)
		if len([]rune(nick)) > 32 {
			return nil, fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
		}
		updates["nickname"] = nick
	}

	if len(updates) == 0 {
		return a, nil
	}
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		// 并发改名撞唯一索引，同样按占用处理。
		return nil, ErrUsernameTaken
	}
	return s.LoadAdmin(id)
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
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	// 角色或状态变更后，让该账号的旧令牌立即失效。
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// DeleteAdmin 删除管理员。不允许删除自己，也不允许删除最后一个超级管理员。
func (s *Services) DeleteAdmin(id, operatorID uint) error {
	if id == operatorID {
		return fmt.Errorf("%w: 不能删除当前登录的账号", ErrInvalidParam)
	}
	target, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if target.Role == "super" {
		if err := s.assertNotLastSuperAdmin(id, "删除"); err != nil {
			return err
		}
	}
	if err := s.DB.Delete(&model.Admin{}, id).Error; err != nil {
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
	res := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// AdminClearTOTP 清除指定管理员的双因素绑定，用于认证器丢失的救援场景。
func (s *Services) AdminClearTOTP(id uint) error {
	res := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{
		"totp_enabled":     false,
		"totp_secret":      "",
		"totp_verified_at": nil,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// assertNotLastSuperAdmin 确保系统里始终至少保留一个可用的超级管理员，
// 否则会出现「谁都进不去后台」的死锁。
func (s *Services) assertNotLastSuperAdmin(excludeID uint, action string) error {
	var n int64
	err := s.DB.Model(&model.Admin{}).
		Where("role = ? AND status = ? AND id <> ?", "super", "active", excludeID).
		Count(&n).Error
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: 系统必须保留至少一个启用的超级管理员，无法%s该账号", ErrInvalidParam, action)
	}
	return nil
}

// ---- 用户管理 ----

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
	u, err := s.insertUser(username, email, in.Password, "", false)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{"remark": truncate(in.Remark, 200)}
	if in.GroupID > 0 {
		updates["group_id"] = in.GroupID
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", u.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	return s.LoadUser(u.ID)
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
		var u model.User
		if err := tx.First(&u, id).Error; err != nil {
			return ErrNotFound
		}
		var tunnels []model.Tunnel
		if err := tx.Where("user_id = ? AND remote_port > 0", id).Find(&tunnels).Error; err != nil {
			return err
		}
		ports = portsOfTunnels(tunnels)
		if err := tx.Where("user_id = ?", id).Delete(&model.Tunnel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.TrafficDaily{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.ClientSession{}).Error; err != nil {
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
	// 残留窗口说明：并发创建且晚于本事务快照的隧道，在 READ COMMITTED
	// 下仍可能被 DELETE 删掉而没进 ports（SQL 没有「删除并返回」的统一
	// 写法，RETURNING 也不是所有方言都支持）。这个窗口比事务外读取小得多，
	// 且需要「删除用户的同时另一路正在建隧道」才会命中。
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
		s.Runtime.SetUserBlocked(id, true)
		// 同时撤销其运行时会话：插件热路径命中会话后只看这两个标记，
		// 但会话本身留着也没有意义——账号都禁用了。
		s.Runtime.DropUserSessions(id)
		return nil
	}
	s.Runtime.SetUserBlocked(id, false)

	// 重新启用时**立即**按真实配额重算，而不是等下一轮流量采集。
	//
	// 禁用期间这个标记被强制置成了 true（上一步）。启用后如果只是放着
	// 不管，就要等到下一次采集成功才会恢复；而采集依赖 frps 管理接口，
	// 它恰好不可用（或采集持续报错）时，用户会看到「账号已启用，但新建
	// 连接一律被拒」，且没有任何地方说明原因。
	if u, err := s.LoadUser(id); err == nil {
		s.Runtime.SetQuotaExceeded(id, s.QuotaExceeded(u))
	} else {
		// 取不到用户（理论上不会走到）时保守放行：
		// 账号状态已经是 active，宁可让下一轮采集再纠正，
		// 也不要因为一次读取失败把用户挡在门外。
		s.Runtime.SetQuotaExceeded(id, false)
	}
	return nil
}

// AdminSetUserQuota 单独设定用户的流量配额（字节）。0 表示回落到分组配额。
func (s *Services) AdminSetUserQuota(id uint, quota int64) error {
	if quota < 0 {
		return fmt.Errorf("%w: 配额不能为负数", ErrInvalidParam)
	}
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Update("traffic_quota", quota)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.refreshQuotaFor(id)
	return nil
}

// AdminResetUserTraffic 清零用户已用流量。
func (s *Services) AdminResetUserTraffic(id uint) error {
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"traffic_used":     0,
		"traffic_reset_at": time.Now().AddDate(0, 1, 0),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.Runtime.SetQuotaExceeded(id, false)
	return nil
}

// AdminSetUserGroup 调整用户分组与到期时间。
func (s *Services) AdminSetUserGroup(id, groupID uint, expireAt *time.Time) error {
	var g model.Group
	if err := s.DB.First(&g, groupID).Error; err != nil {
		return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
	}

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{"group_id": groupID}
		if expireAt != nil {
			updates["group_expire_at"] = *expireAt
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
	s.refreshQuotaFor(id)
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
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, id)
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
func (s *Services) refreshQuotaFor(id uint) {
	u, err := s.LoadUser(id)
	if err != nil {
		return
	}
	s.Runtime.SetQuotaExceeded(u.ID, s.QuotaExceeded(u))
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
	s.refreshQuotaForGroup(id)
	return &g, nil
}

// refreshQuotaForGroup 刷新某分组下所有用户的超额标记。
//
// 一次查询取出该组全部用户（带分组），而不是逐个 LoadUser：
// 一个分组可能有成百上千个用户，逐个查会把一次管理操作变成一串查询。
func (s *Services) refreshQuotaForGroup(groupID uint) {
	var users []model.User
	if err := s.DB.Preload("Group").Where("group_id = ?", groupID).Find(&users).Error; err != nil {
		log.Printf("[quota] 刷新分组 %d 的配额标记失败: %v", groupID, err)
		return
	}
	for i := range users {
		s.EnsureTrafficPeriod(&users[i])
		s.Runtime.SetQuotaExceeded(users[i].ID, s.QuotaExceeded(&users[i]))
	}
}

// DeleteGroup 删除分组。默认分组与仍被占用的分组不允许删除。
func (s *Services) DeleteGroup(id uint) error {
	var g model.Group
	if err := s.DB.First(&g, id).Error; err != nil {
		return ErrNotFound
	}
	if g.IsDefault {
		return fmt.Errorf("%w: 默认分组不允许删除", ErrInvalidParam)
	}
	var used int64
	if err := s.DB.Model(&model.User{}).Where("group_id = ?", id).Count(&used).Error; err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("%w: 仍有 %d 个用户属于该分组，请先迁移", ErrInvalidParam, used)
	}
	res := s.DB.Delete(&model.Group{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- 隧道管理（管理侧）----

// ListAllTunnels 分页查询全部隧道。
func (s *Services) ListAllTunnels(keyword, status string, userID uint, offset, limit int) ([]model.Tunnel, int64, error) {
	q := s.DB.Model(&model.Tunnel{})
	if keyword != "" {
		q = q.Where("name LIKE ?", "%"+keyword+"%")
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.Tunnel
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// AdminSetTunnelStatus 启用/停用任意隧道。
//
// 与用户侧的 SetTunnelStatus 一样必须联动防火墙：停用即收回端口、
// 启用即重新放行。管理员这条路径不联动的话，「停用」只改了数据库，
// 主机防火墙上的规则仍然放行——后台显示已停用，端口其实还开着。
// 而启动时的规则对齐只负责「补开活跃端口」，不会清理这种残留。
func (s *Services) AdminSetTunnelStatus(id uint, status string) error {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return ErrInvalidParam
	}

	// 需要 Type 与 RemotePort 才能操作防火墙，先取出来。
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	if err := s.DB.Model(&model.Tunnel{}).Where("id = ?", id).
		Update("status", status).Error; err != nil {
		return err
	}

	if t.RemotePort > 0 {
		if status == model.TunnelStatusActive {
			s.applyPortIntent(t.RemotePort, ProtoOfTunnel(t.Type), true)
		} else {
			// 与用户侧一致：收回失败要进重试队列，而不是只写一行日志。
			s.applyPortIntent(t.RemotePort, ProtoOfTunnel(t.Type), false)
		}
	}
	return nil
}

// AdminDeleteTunnel 删除任意隧道并回收其端口。
func (s *Services) AdminDeleteTunnel(id uint) error {
	// 端口要在删除前读出来：记录删掉之后就查不回来了，
	// 而防火墙规则会一直留在宿主机上。
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	res := s.DB.Where("id = ?", id).Delete(&model.Tunnel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	if t.RemotePort > 0 {
		s.closePorts([]portProto{{port: t.RemotePort, proto: ProtoOfTunnel(t.Type)}})
	}
	return nil
}

// ListClientSessions 分页查询客户端登录会话。
func (s *Services) ListClientSessions(userID uint, offset, limit int) ([]model.ClientSession, int64, error) {
	q := s.DB.Model(&model.ClientSession{})
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.ClientSession
	err := q.Order("last_seen_at desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// ---- 审计 ----

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
