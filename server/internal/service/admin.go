package service

import (
	"errors"
	"fmt"
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
		if !s.TOTPReplay.Claim(a.ID, step) {
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
	if !s.TOTPReplay.Claim(a.ID, step) {
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
func (s *Services) AdminCreateUser(in AdminCreateUserInput) (*model.User, error) {
	u, err := s.Register(RegisterInput{
		Username: in.Username,
		Password: in.Password,
		Email:    in.Email,
	})
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
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.First(&u, id).Error; err != nil {
			return ErrNotFound
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.Tunnel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.TrafficDaily{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&model.ClientSession{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&model.User{}, id).Error; err != nil {
			return err
		}
		// 内存态同步清理，避免已删除用户仍占用超额标记或身份缓存。
		s.Runtime.SetQuotaExceeded(id, false)
		s.Runtime.InvalidateIdentity(IdentityKindUser, id)
		return nil
	})
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
	// 被封禁的用户需要立刻停止放行流量。
	if status != model.UserStatusActive {
		s.Runtime.SetQuotaExceeded(id, true)
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
	return s.DB.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{"group_id": groupID}
		if expireAt != nil {
			updates["group_expire_at"] = *expireAt
		}
		if err := tx.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		// 分组变化后刷新该用户所有隧道的限速快照。
		if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", id).
			Update("bandwidth_limit", g.BandwidthLimit).Error; err != nil {
			return err
		}
		s.refreshQuotaFor(id)
		return nil
	})
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
	return &g, nil
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
func (s *Services) AdminSetTunnelStatus(id uint, status string) error {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return ErrInvalidParam
	}
	res := s.DB.Model(&model.Tunnel{}).Where("id = ?", id).Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminDeleteTunnel 删除任意隧道。
func (s *Services) AdminDeleteTunnel(id uint) error {
	res := s.DB.Where("id = ?", id).Delete(&model.Tunnel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
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

// WriteAudit 写入管理员操作审计。
func (s *Services) WriteAudit(adminID uint, adminName, action, target, targetID, detail, ip string) {
	_ = s.DB.Create(&model.AuditLog{
		AdminID:   adminID,
		AdminName: adminName,
		Action:    action,
		Target:    target,
		TargetID:  targetID,
		Detail:    truncate(detail, 1000),
		IP:        ip,
	}).Error
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
