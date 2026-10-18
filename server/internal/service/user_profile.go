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
func (s *Services) UpdateProfile(userID uint, in ProfileUpdateInput) (*model.User, error) {
	u, err := s.LoadUser(userID)
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}
	renamed := false
	emailChanged := false

	if in.Username != nil {
		name := strings.TrimSpace(*in.Username)
		if name != u.Username {
			if len(name) < 3 || len(name) > 32 || !isSafeName(name) {
				return nil, fmt.Errorf("%w: 用户名需为 3-32 位字母、数字或下划线", ErrInvalidParam)
			}
			var n int64
			if err := s.DB.Model(&model.User{}).Where("username = ?", name).Count(&n).Error; err != nil {
				return nil, err
			}
			if n > 0 {
				return nil, ErrUsernameTaken
			}
			updates["username"] = name
			renamed = true
		}
	}

	if in.Nickname != nil {
		nick := strings.TrimSpace(*in.Nickname)
		if len([]rune(nick)) > 32 {
			return nil, fmt.Errorf("%w: 昵称不得超过 32 个字符", ErrInvalidParam)
		}
		updates["nickname"] = nick
	}

	if in.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*in.Email))
		if email != "" && !IsValidEmail(email) {
			return nil, fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		// 换邮箱必须走验证流程（见 RequestEmailChange）：要有当前密码，还要
		// 新地址收得到验证码，否则拿到一个被盗会话的人可以先改成自己的邮箱、
		// 再用「找回密码」长期接管。站点没开邮件时邮箱只是联系方式，找不回
		// 密码，直接保存没有提权风险，但仍要清掉旧地址的「已验证」与恢复凭据。
		//
		// 「是否真的换了」与「是否需要验证」都在 changeEmailLocked 里用行锁后的
		// 当前值判断，不能用开头读到的 u.Email 这个过期快照——并发换绑会漏清
		// 或覆盖。email_domain 不跟着改：它记的是注册来源域名，用于单域名每日
		// 注册额度统计，跟着改等于换一次邮箱就退回原域名的当日额度。
		changed, err := s.changeEmailLocked(userID, email, true, false)
		if err != nil {
			return nil, err
		}
		emailChanged = changed
	}

	if len(updates) == 0 && !emailChanged {
		return u, nil
	}
	if len(updates) > 0 {
		if err := s.DB.Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
			// 只有唯一索引冲突（并发改名）按占用处理。昵称等普通字段写失败也
			// 报「用户名已被占用」会把排查方向直接带偏——用户会去改名，而真实
			// 原因是一次写库失败。
			if isUniqueConflict(err) {
				return nil, ErrUsernameTaken
			}
			return nil, err
		}
	}
	if renamed {
		// 会话表里的用户名仅用于后台展示，改名后同步，避免显示旧值。
		_ = s.DB.Model(&model.ClientSession{}).Where("user_id = ?", userID).
			Update("username", updates["username"]).Error
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
