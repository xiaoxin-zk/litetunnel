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

// AdminTOTPSetup 生成一把**待确认**的新 TOTP 密钥。
//
// 两步式设计（先生成、再用一次正确口令确认）是为了避免用户扫码失败后
// 就把自己锁在门外。
//
// # 已启用时不能凭会话令牌直接换绑
//
// 如果不加约束，一个**被盗的管理员会话令牌**就足以把第二因素整个换掉：
// 攻击者调用它、绑上自己控制的密钥，第二因素从此形同虚设——而「关闭双因素」
// 那个接口反倒要求重新验证口令，成了两者中更严格的一个，这明显不对。
//
// 所以已启用时要求提供**当前生效的动态口令**：换绑的正当场景是「换了手机」，
// 此时旧设备还在手上。旧设备也丢了的话，由超级管理员在管理员列表里重置
// （POST /admins/:id/totp-reset，权限更高且会记审计）。
//
// # 新密钥只暂存，不动生效的那把
//
// 生成之后写进 totp_pending_secret，totp_secret / totp_enabled **保持原样**，
// 等管理员用新设备的口令调 Enable 验证通过才原子切换。
//
// 直接替换（并把 totp_enabled 置回 false）会留下一个危险的中间态：确认这一步
// 要等用户去扫码、输码，中间只要关掉页面、网络中断或输错，账号就停在
// 「只有密码保护」——而用户以为自己正在换绑，多半不会察觉第二因素已经没了。
// 暂存之后，未完成的换绑等于什么都没发生。
func (s *Services) AdminTOTPSetup(id uint, code string) (secret, otpauthURL string, err error) {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return "", "", err
	}

	if a.TOTPEnabled {
		if strings.TrimSpace(code) == "" {
			return "", "", fmt.Errorf(
				"%w: 双因素认证已启用，换绑需要输入当前动态口令（设备已丢失请联系超级管理员重置）",
				ErrInvalidParam)
		}
		step, ok := auth.VerifyTOTPStep(a.TOTPSecret, code, time.Now())
		if !ok {
			return "", "", ErrTOTPInvalid
		}
		// 与登录、绑定一致，这一步的口令也要登记：否则同一个口令可以被拿去
		// 连续做两次操作（换绑 + 登录），防重放就出现了一个缺口。
		if !s.ClaimTOTPStep(a.ID, step) {
			return "", "", ErrTOTPReplay
		}
	}

	secret, err = auth.GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", id).
		Update("totp_pending_secret", secret).Error; err != nil {
		return "", "", err
	}
	return secret, auth.OtpauthURL("LiteTunnel", a.Username, secret), nil
}

// AdminTOTPEnable 用一次正确的动态口令确认绑定（或完成换绑）。
//
// 待确认密钥存在时走**换绑**：验证新设备的口令，然后把它原子地提升为生效密钥
// ——提升条件里带着「待确认密钥仍是我们刚验证的那把」，因此并发的两次确认
// 只有一个能成功，另一个会拿到「重放」。
//
// 没有待确认密钥时走**首次绑定**：验证的是刚生成的那把密钥本身。
func (s *Services) AdminTOTPEnable(id uint, code string) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}

	// 换绑期间优先验证待确认的那把；否则验证当前生效的（首次绑定）。
	pending := a.TOTPPendingSecret
	target := pending
	if target == "" {
		target = a.TOTPSecret
	}
	if target == "" {
		return fmt.Errorf("%w: 请先生成密钥", ErrInvalidParam)
	}

	step, ok := auth.VerifyTOTPStep(target, code, time.Now())
	if !ok {
		return ErrTOTPInvalid
	}
	now := time.Now()

	if pending != "" {
		// 原子切换：把待确认密钥提升为生效密钥，并清掉暂存。
		//
		// 条件里带上「待确认密钥仍是刚验证的那把」，于是：
		//   - 并发两次确认只有一个成功（另一个 RowsAffected=0）；
		//   - 期间又调了一次 Setup 换了新密钥的话，这次确认作废——否则会用
		//     一个已经被替换掉的密钥把 2FA 打开。
		//
		// 水位线一并置为本次验证的步进：旧密钥的水位线对新密钥没有意义，
		// 而且这样这个刚用过的口令也不会被重放。
		//
		// token_version 也在同一个 UPDATE 里递增（换绑即撤销既有会话，
		// 见 updateAdminSecurity）：换绑的前提往往是设备丢失或疑似泄露，
		// 此刻最该停止信任的就是既有会话。
		res := s.DB.Model(&model.Admin{}).
			Where("id = ? AND totp_pending_secret = ?", id, pending).
			Updates(map[string]any{
				"totp_secret":         pending,
				"totp_pending_secret": "",
				"totp_enabled":        true,
				"totp_last_step":      step,
				"totp_verified_at":    now,
				"token_version":       gorm.Expr("token_version + 1"),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrTOTPReplay
		}
		s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
		return nil
	}

	// 首次绑定：登记这一步，避免「刚绑定完立刻拿同一个口令去登录」。
	if !s.ClaimTOTPStep(a.ID, step) {
		return ErrTOTPReplay
	}
	return s.updateAdminSecurity(id, map[string]any{
		"totp_enabled":     true,
		"totp_verified_at": now,
	})
}

// updateAdminSecurity 写入一次安全相关的管理员状态变更，并撤销其既有会话。
//
// # 会话策略
//
// **任何改变动态口令绑定的操作**——启用、换绑、关闭、超管救援重置——都会让该
// 管理员已签发的令牌立即失效：递增 token_version（校验时会比对），并清掉身份
// 缓存（令牌只验签、不查库，缓存不清的话已登录会话在缓存过期前仍会被放行）。
//
// 为什么这类操作要踢人下线：它们的前提往往是「设备丢失或疑似泄露」，而此刻最该
// 停止信任的恰恰是既有会话——一个被盗的令牌可能正是这次操作要处理的东西。
// 这与改密码、改角色/状态采用同一套语义。
//
// 注意**只在状态真的改变时**才调用：把已经关闭的双因素再关一次也把人踢下线，
// 只会让管理员在无意义的操作里莫名被登出（改角色那处也是这么处理的）。
func (s *Services) updateAdminSecurity(id uint, updates map[string]any) error {
	updates["token_version"] = gorm.Expr("token_version + 1")
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	return nil
}

// AdminTOTPDisable 关闭双因素认证。
//
// 关闭是降级安全等级的操作，必须重新验证登录口令，
// 避免令牌被盗后攻击者直接关掉第二因素。
//
// 关闭同样撤销既有会话（见 updateAdminSecurity）：这是一次「第二因素没了」的
// 状态变化，此刻继续沿用旧会话等于让降级前的信任无限延续下去。
func (s *Services) AdminTOTPDisable(id uint, password string) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(a.Password, password) {
		return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
	}
	if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
		// 本来就没绑定：什么都没变，不该因为一次空操作把人踢下线。
		return nil
	}
	return s.updateAdminSecurity(id, map[string]any{
		"totp_enabled": false,
		"totp_secret":  "",
		// 待确认的密钥一并清掉：关闭之后它没有意义，留着只会在下次绑定时
		// 被当成「正在换绑」。
		"totp_pending_secret": "",
	})
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
	// 真正的守卫在 applyAdminUpdate 里：上面那次数量检查只负责给出准确的报错，
	// 并发下它可能已经过时。
	if err := s.applyAdminUpdate(id, target, updates); err != nil {
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
func (s *Services) applyAdminUpdate(id uint, target *model.Admin, updates map[string]any) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := assertSuperAdminRemainsAfterUpdate(tx, target, updates); err != nil {
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
		if target.Role == "super" {
			if err := assertNotLastSuperAdminIn(tx, target.ID, "删除"); err != nil {
				return err
			}
		}
		return tx.Delete(&model.Admin{}, target.ID).Error
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
//
// 这是最该撤销既有会话的一处：走到这里说明账号很可能已经出过问题
// （设备丢失、疑似泄露），而执行救援的超级管理员无法判断目标账号当前
// 还有哪些会话在活动——全部作废，让持有人重新登录并绑定新设备。
func (s *Services) AdminClearTOTP(id uint) error {
	a, err := s.LoadAdmin(id)
	if err != nil {
		return err
	}
	if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
		// 没有可清除的绑定：不改变任何状态，也不该把人踢下线。
		return nil
	}
	return s.updateAdminSecurity(id, map[string]any{
		"totp_enabled":        false,
		"totp_secret":         "",
		"totp_pending_secret": "",
		"totp_verified_at":    nil,
	})
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

// ---- 用户管理 ----
