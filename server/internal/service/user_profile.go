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

// ProfileUpdateInput 用户自助修改资料的入参。
// 全部使用指针，用于区分「未提交该字段」与「提交了空值」。
type ProfileUpdateInput struct {
	Username *string `json:"username"`
	Nickname *string `json:"nickname"`
	Email    *string `json:"email"`
}

// UpdateProfile 用户修改自己的账号资料。
//
// 允许修改用户名：frp 配置里的 user 字段已改为不可变的用户 ID（lt_u<id>），
// 插件与流量采集均以 ID 为准，因此改名不会导致已下发的客户端配置失效。
//
// 这里只做格式校验；「是否真的变了」与唯一性都必须放到事务里用行锁后的
// 快照判断（见 updateProfileLocked）。
func (s *Services) UpdateProfile(userID uint, in ProfileUpdateInput) (*model.User, error) {
	fields := map[string]any{}

	if in.Username != nil {
		name := strings.TrimSpace(*in.Username)
		if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
			return nil, fmt.Errorf("%w: 用户名需为 3-32 位字母、数字或下划线", ErrInvalidParam)
		}
		fields["username"] = name
	}

	if in.Nickname != nil {
		nick := strings.TrimSpace(*in.Nickname)
		if len([]rune(nick)) > 32 {
			return nil, fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
		}
		fields["nickname"] = nick
	}

	var email *string
	if in.Email != nil {
		e := strings.ToLower(strings.TrimSpace(*in.Email))
		if e != "" && !IsValidEmail(e) {
			return nil, fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		email = &e
	}

	if len(fields) == 0 && email == nil {
		return s.LoadUser(userID)
	}
	// 换邮箱必须走验证流程（见 RequestEmailChange）：要有当前密码，还要新
	// 地址收得到验证码，否则拿到一个被盗会话的人可以先改成自己的邮箱、再用
	// 「找回密码」长期接管。站点没开邮件时邮箱只是联系方式，找不回密码，
	// 直接保存没有提权风险——但仍要清掉旧地址的「已验证」与恢复凭据。
	return s.updateProfileLocked(userID, profilePatch{
		email:                    email,
		requireEmailVerification: true,
		fields:                   fields,
	})
}

// profilePatch 是一次资料变更的全部内容，字段都已通过格式校验。
type profilePatch struct {
	// email 非 nil 表示要改邮箱；里面的值已归一化为小写。
	email *string
	// requireEmailVerification 为真时，改邮箱必须先走「更换邮箱」验证流程。
	requireEmailVerification bool
	// bumpTokenVersion 为真时改邮箱顺带自增 token_version，让既有网页会话失效。
	bumpTokenVersion bool
	// fields 是要写回用户表的其它列（username / nickname / remark）。
	fields map[string]any
}

// updateProfileLocked 是「资料变更」唯一的落库点。
//
// 为什么必须整组放进同一把用户锁、同一个事务：
//
// 以前邮箱先单独提交，昵称/备注/用户名随后再提交。后一步失败时接口返回
// 失败，而邮箱已经改了——用户看到「保存失败」，再试一次却可能撞上
// 「邮箱已被占用」（占用者就是他自己），只能去后台改。更糟的是管理员
// 改邮箱时会顺带重置 token_version 并撤销旧地址的恢复凭据，这些副作用
// 都已经生效，界面上却是一次失败。
func (s *Services) updateProfileLocked(userID uint, p profilePatch) (*model.User, error) {
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	emailChanged := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁用户行再读当前值：唯一性检查、「是否真的变了」都必须基于
		// 锁住之后的那一份，否则并发换绑会互相覆盖。
		var cur model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&cur, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		if p.email != nil {
			want := strings.ToLower(strings.TrimSpace(*p.email))
			if want != strings.ToLower(strings.TrimSpace(cur.Email)) {
				if p.requireEmailVerification && s.MailEnabled() {
					return fmt.Errorf("%w: 修改邮箱需要验证新地址，请使用「更换邮箱」流程", ErrInvalidParam)
				}
				if want != "" {
					var taken int64
					if err := tx.Model(&model.User{}).
						Where("lower(email) = ? AND id <> ?", want, userID).
						Count(&taken).Error; err != nil {
						return err
					}
					if taken > 0 {
						return ErrEmailTaken
					}
				}
				updates := map[string]any{
					"email":          want,
					// 「已验证」针对的是具体地址：换绑后必须撤销。
					"email_verified": false,
					// email_domain 不跟着改：它记的是注册来源域名，用于单域名
					// 每日注册额度统计，跟着改等于换一次邮箱就退回当日额度。
				}
				if p.bumpTokenVersion {
					updates["token_version"] = gorm.Expr("token_version + 1")
				}
				if err := tx.Model(&model.User{}).Where("id = ?", userID).
					Updates(updates).Error; err != nil {
					return err
				}
				// 旧地址的恢复凭据一并作废：换绑之后旧邮箱收到的重置链接
				// 仍然指向这个账号，留着等于给旧邮箱的主人一条后路。
				if err := purgeEmailCredentialsTx(tx, userID, cur.Email); err != nil {
					return err
				}
				emailChanged = true
			}
		}

		if len(p.fields) == 0 {
			return nil
		}
		// 用户名唯一性在事务内检查：锁外先查一遍再写，中间可以插进一次
		// 同名的改名，最后靠唯一索引兜底报一个与「占用」无关的写库错误。
		if name, ok := p.fields["username"]; ok {
			var taken int64
			if err := tx.Model(&model.User{}).
				Where("username = ? AND id <> ?", name, userID).
				Count(&taken).Error; err != nil {
				return err
			}
			if taken > 0 {
				return ErrUsernameTaken
			}
		}
		if res := tx.Model(&model.User{}).Where("id = ?", userID).
			Updates(p.fields); res.Error != nil {
			// 只有唯一索引冲突（并发改名）按占用处理。昵称等普通字段写失败
			// 也报「用户名已被占用」会把排查方向直接带偏。
			if isUniqueConflict(res.Error) {
				return ErrUsernameTaken
			}
			return res.Error
		}
		if name, ok := p.fields["username"]; ok {
			// 会话表里的用户名仅用于后台展示，改名后同步，避免显示旧值。
			if err := tx.Model(&model.ClientSession{}).Where("user_id = ?", userID).
				Update("username", name).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if emailChanged && p.bumpTokenVersion {
		// 身份缓存只在内存里，事务提交后再失效。
		s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	}
	return s.LoadUser(userID)
}

// RequestEmailChange 是「更换邮箱」的第一步：校验密码后给**新地址**发验证码。
//
// 三道关卡缺一不可：
//
//  1. 当前密码 —— 证明操作者是账号本人，而不只是一个被盗的会话令牌；
//  2. 新邮箱未被他人占用 —— 否则「找回密码」会把验证码发到别人的账号上，
//     按邮箱查账号的结果也不确定；
//  3. 新地址收得到验证码 —— 证明这个地址确实属于你（见 ConfirmEmailChange）。
//
// 只做格式校验就写库的话，攻击路径是现成的：改邮箱 → 用自己的邮箱收重置码
// → 设新密码，把一次临时入侵升级成长期控制。
func (s *Services) RequestEmailChange(userID uint, newEmail, password, ip string) error {
	u, err := s.LoadUser(userID)
	if err != nil {
		return err
	}
	if !auth.VerifyPassword(u.Password, password) {
		return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
	}
	email := strings.ToLower(strings.TrimSpace(newEmail))
	if !IsValidEmail(email) {
		return ErrEmailRequired
	}
	if email == strings.ToLower(strings.TrimSpace(u.Email)) {
		return fmt.Errorf("%w: 新邮箱与当前邮箱相同", ErrInvalidParam)
	}
	return s.SendEmailCode(email, EmailSceneChange, ip)
}

// ConfirmEmailChange 是「更换邮箱」的第二步：校验新地址收到的验证码并换绑。
func (s *Services) ConfirmEmailChange(userID uint, newEmail, code string) error {
	email := strings.ToLower(strings.TrimSpace(newEmail))
	if !IsValidEmail(email) {
		return ErrEmailRequired
	}

	rec, err := s.checkEmailCode(s.DB, email, EmailSceneChange, code)
	if err != nil {
		return err
	}

	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 锁住用户行，与「激活重置令牌」串行（那边也锁这一行）。
		//
		// 不锁的话存在这条交错：激活事务查到「邮箱还是旧的」，本事务随后
		// 提交（删掉旧令牌、把旧邮件标成失败），激活事务最后才插入令牌——
		// 清理之后又冒出一份可用的旧链接。锁上之后只剩两种顺序：
		// 激活先完成（随后被这里删掉），或本事务先完成（那边查到的邮箱已变，作废）。
		var old model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&old, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		// 唯一性在事务里再判一次：两个账号可能同时确认同一个新邮箱。
		var taken int64
		if err := tx.Model(&model.User{}).
			Where("lower(email) = ? AND id <> ?", email, userID).
			Count(&taken).Error; err != nil {
			return err
		}
		if taken > 0 {
			return ErrEmailTaken
		}

		// 消费验证码与换绑必须同生共死：只消费不改，用户得重新申请；
		// 只改不消费，同一个码还能再用一次。
		if err := s.consumeEmailCode(tx, rec.ID); err != nil {
			return err
		}

		// email_domain 不跟着改：它记的是注册来源域名，用于单域名每日
		// 注册额度统计。跟着改等于换一次邮箱就把原域名的额度退回去。
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
			"email": email,
			// 新地址刚刚收到并回填了验证码：标记为已验证。
			// 旧地址的「已验证」不能沿用到新地址上，这正是这里显式赋值的原因。
			"email_verified": true,
		}).Error; err != nil {
			return err
		}

		// 旧地址与旧凭据一并作废：换绑之后，旧邮箱收到的重置链接/验证码
		// 仍然指向这个账号，留着等于给旧邮箱的主人一条后路。
		return purgeEmailCredentialsTx(tx, userID, old.Email)
	})
}
