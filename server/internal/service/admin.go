package service

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
//
// 必须先在采集器登记待协调标记、再清零（见 Runtime.pendingTrafficReset）：
// 清零后紧邻一轮的增量是清零前采样的旧流量，不拦的话最多一个采样周期后
// 它会重新加回用户用量——管理员看到「明明清零了又涨回来了」。
// 顺序反过来（先清零后登记）会有一个窗口：增量恰好插在两步之间落库，
// 标记拦不住它。
func (s *Services) AdminResetUserTraffic(id uint) error {
	s.Runtime.MarkTrafficResetPending(id)
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"traffic_used":     0,
		"traffic_reset_at": time.Now().AddDate(0, 1, 0),
	})
	if res.Error != nil {
		// 清零没写进去，登记的标记必须撤销：留着它，后续采集会错误地
		// 丢弃一轮**真实**用量。
		s.Runtime.UnmarkTrafficResetPending(id)
		return res.Error
	}
	if res.RowsAffected == 0 {
		s.Runtime.UnmarkTrafficResetPending(id)
		return ErrNotFound
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(id, false)
	return nil
}

// AdminSetUserGroup 调整用户分组与到期时间。
//
// 分组的存在性检查、用户行的更新放进同一事务，并按全局锁序
// （用户行 → 分组行，与 Redeem 一致）对两张行加 FOR UPDATE：
// 只在事务外查一下分组的话，「检查通过 → 更新用户」之间分组可能被删，
// 写出一个悬空的 group_id。
func (s *Services) AdminSetUserGroup(id, groupID uint, expireAt *time.Time) error {
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
//
// 这是管理路径的直写：先递增版本号（见 Runtime.guardVer），
// 让在途的后台整表刷新识别「快照已过时」并让路。
func (s *Services) refreshQuotaFor(id uint) {
	u, err := s.LoadUser(id)
	if err != nil {
		return
	}
	s.Runtime.BumpGuardVer()
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
	// 版本号在读库之前取：这是管理路径的直写，同样要让在途的后台
	// 整表刷新让路（见 Runtime.guardVer）。
	s.Runtime.BumpGuardVer()
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
// 只负责「按 id 圈定目标」，状态切换与副作用全部交给 setTunnelStatus，
// 与用户侧共用同一套实现。这条路径原先自己写了一遍状态变更，于是漏掉了
// 用户侧有、这里没有的 HTTPS 入口校验：平台切回边缘模式后，管理员仍能把
// 旧 HTTPS 隧道重新启用，得到一条状态为运行中、实际永远连不上的隧道。
//
// 联动防火墙同样必须共用：不联动的话「停用」只改了数据库，主机防火墙上的
// 规则仍然放行——后台显示已停用，端口其实还开着。而启动时的规则对齐只负责
// 「补开活跃端口」，不会清理这种残留。
func (s *Services) AdminSetTunnelStatus(id uint, status string) error {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return ErrInvalidParam
	}

	// 需要 Type 与 RemotePort 才能校验入口、操作防火墙，先取出来。
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.setTunnelStatus(&t, status)
}

// AdminDeleteTunnel 删除任意隧道并回收其端口。
//
// 持隧道归属者的用户锁：与该用户的编辑、启停隧道共用（见 UpdateTunnel）。
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

	// 锁在读完归属者之后取：与 setTunnelStatus、DeleteTunnel 的锁序一致
	// （先读记录、再按归属者锁住整个变更段）。
	lock := s.userLock(t.UserID)
	lock.Lock()
	defer lock.Unlock()

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
