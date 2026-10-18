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

// 管理员认证与安全：登录、双因素认证（TOTP）绑定/换绑/关闭/救援清除，
// 以及相关的会话撤销。

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
		// 审计字段写失败不让登录失败（认证已经通过，卡在这里等于把一次
		// 正确的第二因素验证变成「登录失败」），但必须留痕：否则后台会
		// 长期显示旧时间，排查「谁在什么时候用过动态口令」时被误导。
		if err := s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
			Update("totp_verified_at", now).Error; err != nil {
			log.Printf("[admin] 记录管理员 %d 的 TOTP 验证时间失败（认证已通过，审计字段未更新）: %v", a.ID, err)
		} else {
			a.TOTPVerifiedAt = &now
		}
	}

	now := time.Now()
	// 同上：内存里的返回值只在写库成功后才更新，避免接口回显一个
	// 数据库里并不存在的时间。
	if err := s.DB.Model(&model.Admin{}).Where("id = ?", a.ID).
		Updates(map[string]any{"last_login_at": now, "last_login_ip": ip}).Error; err != nil {
		log.Printf("[admin] 记录管理员 %d 的登录时间/IP 失败（登录已通过，审计字段未更新）: %v", a.ID, err)
	} else {
		a.LastLoginAt = &now
		a.LastLoginIP = ip
	}
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
	var username, generated string
	err = s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		username = a.Username
		if a.TOTPEnabled {
			if strings.TrimSpace(code) == "" {
				return false, fmt.Errorf(
					"%w: 双因素认证已启用，换绑需要输入当前动态口令（设备已丢失请联系超级管理员重置）",
					ErrInvalidParam)
			}
			step, ok := auth.VerifyTOTPStep(a.TOTPSecret, code, time.Now())
			if !ok {
				return false, ErrTOTPInvalid
			}
			// 与登录、绑定一致，这一步的口令也要登记：否则同一个口令可以被拿去
			// 连续做两次操作（换绑 + 登录），防重放就出现了一个缺口。
			if !s.ClaimTOTPStepTx(tx, a.ID, step) {
				return false, ErrTOTPReplay
			}
		}

		var gerr error
		generated, gerr = auth.GenerateTOTPSecret()
		if gerr != nil {
			return false, gerr
		}
		if err := tx.Model(&model.Admin{}).Where("id = ?", id).
			Update("totp_pending_secret", generated).Error; err != nil {
			return false, err
		}
		// 只暂存待确认密钥，不动生效的那把：不撤销会话。
		return false, nil
	})
	if err != nil {
		return "", "", err
	}
	return generated, auth.OtpauthURL("LiteTunnel", username, generated), nil
}

// AdminTOTPEnable 用一次正确的动态口令确认绑定（或完成换绑）。
//
// 待确认密钥存在时走**换绑**：验证新设备的口令，然后把它原子地提升为生效密钥
// ——提升条件里带着「待确认密钥仍是我们刚验证的那把」，因此并发的两次确认
// 只有一个能成功，另一个会拿到「重放」。
//
// 没有待确认密钥时走**首次绑定**：验证的是刚生成的那把密钥本身。
func (s *Services) AdminTOTPEnable(id uint, code string) error {
	return s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		// 换绑期间优先验证待确认的那把；否则验证当前生效的（首次绑定）。
		pending := a.TOTPPendingSecret
		target := pending
		if target == "" {
			target = a.TOTPSecret
		}
		if target == "" {
			return false, fmt.Errorf("%w: 请先生成密钥", ErrInvalidParam)
		}

		step, ok := auth.VerifyTOTPStep(target, code, time.Now())
		if !ok {
			return false, ErrTOTPInvalid
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
			// token_version 也在同一个 UPDATE 里递增（换绑即撤销既有会话）：
			// 换绑的前提往往是设备丢失或疑似泄露，此刻最该停止信任的就是既有会话。
			res := tx.Model(&model.Admin{}).
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
				return false, res.Error
			}
			if res.RowsAffected == 0 {
				return false, ErrTOTPReplay
			}
			return true, nil
		}

		// 首次绑定：登记这一步，避免「刚绑定完立刻拿同一个口令去登录」。
		if !s.ClaimTOTPStepTx(tx, a.ID, step) {
			return false, ErrTOTPReplay
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled":     true,
			"totp_verified_at": now,
		})
	})
}

// withAdminSecurity 在管理员锁内串行执行一次安全状态变更，并在事务内
// FOR UPDATE 重读目标行。
//
// 绑定/换绑/关闭/救援重置这些操作并发时，若各自「先读再写」，会互相覆盖
// 密钥状态（例如关闭把刚换绑的新密钥清掉），或让令牌撤销与双因素状态
// 不一致。统一走这一个入口，让「读取-校验-写入」在同一把锁、同一个事务里
// 原子完成。
//
// fn 返回 changed 表示状态真的变了（据此决定是否撤销既有会话）；返回 error
// 则整个事务回滚、不撤销会话。会话策略见下方注释：**任何改变动态口令绑定
// 的操作**都要让该管理员已签发的令牌立即失效——递增 token_version 并清掉
// 身份缓存，因为这类操作的前提往往是「设备丢失或疑似泄露」，此刻最该停止
// 信任的恰恰是既有会话。
//
// 注意**只在状态真的改变时**才返回 changed：把已经关闭的双因素再关一次也
// 把人踢下线，只会让管理员在无意义的操作里莫名被登出。
func (s *Services) withAdminSecurity(id uint, fn func(tx *gorm.DB, a *model.Admin) (bool, error)) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	var changed bool
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		c, ferr := fn(tx, &a)
		changed = c
		return ferr
	})
	if err != nil {
		return err
	}
	if changed {
		s.Runtime.InvalidateIdentity(IdentityKindAdmin, id)
	}
	return nil
}

// updateAdminSecurityTx 在事务内写入一次安全状态变更：递增 token_version + 写字段。
//
// 是否撤销会话由 withAdminSecurity 根据 changed 统一处理，这里只负责那半次
// 数据库写入，避免各调用方重复调用 InvalidateIdentity。
func (s *Services) updateAdminSecurityTx(tx *gorm.DB, id uint, updates map[string]any) error {
	updates["token_version"] = gorm.Expr("token_version + 1")
	return tx.Model(&model.Admin{}).Where("id = ?", id).Updates(updates).Error
}

// AdminTOTPDisable 关闭双因素认证。
//
// 关闭是降级安全等级的操作，必须重新验证登录口令，
// 避免令牌被盗后攻击者直接关掉第二因素。
//
// 关闭同样撤销既有会话（见 updateAdminSecurity）：这是一次「第二因素没了」的
// 状态变化，此刻继续沿用旧会话等于让降级前的信任无限延续下去。
func (s *Services) AdminTOTPDisable(id uint, password string) error {
	return s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		if !auth.VerifyPassword(a.Password, password) {
			return false, fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
		}
		if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
			// 本来就没绑定：什么都没变，不该因为一次空操作把人踢下线。
			return false, nil
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled": false,
			"totp_secret":  "",
			// 待确认的密钥一并清掉：关闭之后它没有意义，留着只会在下次绑定时
			// 被当成「正在换绑」。
			"totp_pending_secret": "",
		})
	})
}

// AdminChangePassword 管理员修改自己的登录密码。
//
// 管理员口令是平台的最高权限入口，因此策略比普通用户更严格：
// 长度不少于 12 位，且不允许与原密码相同。
func (s *Services) AdminChangePassword(id uint, oldPassword, newPassword string) error {
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

	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// 在锁内重读目标行：并发改密时，事务外读到的旧密码已经过时，用它
		// 验证会把「已被他人改掉」的旧密码当成有效凭据。FOR UPDATE 锁住这
		// 一行，让「验旧密码」与「写新密码」原子完成。
		var a model.Admin
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if !auth.VerifyPassword(a.Password, oldPassword) {
			return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
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

// AdminClearTOTP 清除指定管理员的双因素绑定，用于认证器丢失的救援场景。
//
// 这是最该撤销既有会话的一处：走到这里说明账号很可能已经出过问题
// （设备丢失、疑似泄露），而执行救援的超级管理员无法判断目标账号当前
// 还有哪些会话在活动——全部作废，让持有人重新登录并绑定新设备。
func (s *Services) AdminClearTOTP(id uint) error {
	return s.withAdminSecurity(id, func(tx *gorm.DB, a *model.Admin) (bool, error) {
		if !a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPPendingSecret == "" {
			// 没有可清除的绑定：不改变任何状态，也不该把人踢下线。
			return false, nil
		}
		return true, s.updateAdminSecurityTx(tx, id, map[string]any{
			"totp_enabled":        false,
			"totp_secret":         "",
			"totp_pending_secret": "",
			"totp_verified_at":    nil,
		})
	})
}
