package service

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// emailCodePayload 是「邮箱验证码」类邮件的凭据参数。
//
// 验证码记录**不在这封信进发件箱时就创建**，而是等它真的送达之后才创建：
// 只有这样，投递失败时才不会出现「新码没到、旧码已废」的窘境。
//
// 有效期同样从**送达时刻**起算（存 TTL 而不是绝对时间）。存绝对时间的话，
// 发件箱重试（1/2/4/8 分钟）加上积压，很容易让用户收到一个已经过期的码：
// 邮件正文写着「10 分钟内有效」，而实际上它一到手就已经失效。
type emailCodePayload struct {
	Email    string `json:"email"`
	Scene    string `json:"scene"`
	CodeHash string `json:"code_hash"`
	// TTLSeconds 是验证码自**送达**起的有效秒数。
	TTLSeconds int    `json:"ttl_seconds"`
	IP         string `json:"ip"`
	// TokenVersion 是找回密码验证码**入队时**用户的令牌版本。
	//
	// 验证码同样是送达后才创建的（见 activateEmailCode），改密时撤销不到
	// 还不存在的记录。激活时比对版本：不一致说明期间改过密码，这封邮件作废。
	// 指针用于兼容升级前入队的邮件（nil 表示没有快照）。
	TokenVersion *int `json:"token_version,omitempty"`
}

// resetLinkPayload 是「重置密码链接」类邮件的凭据参数。
//
// TTL 的含义同上：从送达时刻起算，而不是从入队时刻。
type resetLinkPayload struct {
	UserID     uint   `json:"user_id"`
	TokenHash  string `json:"token_hash"`
	TTLSeconds int    `json:"ttl_seconds"`
	IP         string `json:"ip"`
	// TokenVersion 是**入队时**用户的令牌版本。
	//
	// 令牌是在邮件送达时才创建的（见 activateResetToken），所以「改密发生在
	// 入队与送达之间」这条路径上，撤销令牌是撤不到它的——那时它还不存在。
	// 激活时比对这个版本：不一致说明期间改过密码，这封信里的链接必须作废。
	//
	// 指针是为了兼容升级前入队的邮件：老载荷没有这个字段（nil），按原行为处理。
	TokenVersion *int `json:"token_version,omitempty"`
}

// errMailActionSuperseded 表示该邮件的凭据动作已被**更新的同类凭据**取代，
// 激活被有意跳过（见 activateEmailCode / activateResetToken 的取代判定）。
// finishMailAction 据此把记录标成已办结，而不是当成失败去重试。
var errMailActionSuperseded = errors.New("已被更新的凭据取代")

// errMailActionObsolete 表示凭据动作的目标账号已不存在（被管理员删除），
// 动作整体作废：重试再多次也不会成功，按已办结处理。
var errMailActionObsolete = errors.New("目标账号已不存在，凭据动作作废")

// applyMailAction 在邮件**确认送达之后**让新凭据生效，并作废同类的旧凭据。
//
// # 为什么必须等到送达
//
// 以前的顺序是「写队列 → 立即作废旧凭据」。而队列在内存里、发送失败只记一行
// 日志：信没发出去，旧凭据却已经废了，用户手上一个可用的凭据都没有——
// 账号就此找不回来，而且他每点一次「重新发送」都重复这个过程。
//
// 现在顺序反过来：送达到才生效。投递失败只是「这次没收到」，
// 用户原有的凭据仍然可用，可以随时再试。
func (s *Services) applyMailAction(row model.MailOutbox, token string) error {
	switch row.Kind {
	case model.MailKindEmailCodeRegister, model.MailKindEmailCodeReset, model.MailKindEmailCodeChange:
		return s.activateEmailCode(row, token)
	case model.MailKindResetLink:
		return s.activateResetToken(row, token)
	default:
		// 未知类型：邮件已经发出去了，但没有凭据要激活。
		// 不报错——报错会把它标成 failed，而实际上信是发出去的。
		return nil
	}
}

// stillClaimed 在事务内确认这封信仍由本次领取持有。
//
// 多实例时租约可能过期、被别的实例接手；也可能在这期间被作废
// （换邮箱会把旧地址的邮件标成失败并清空参数）。这两种情况下都不该
// 再激活凭据——否则会出现「清理之后又被写回一份可用令牌」。
func stillClaimed(tx *gorm.DB, rowID uint, token string) error {
	var n int64
	if err := tx.Model(&model.MailOutbox{}).
		Where("id = ? AND status = ? AND claim_token = ?", rowID, model.MailActivating, token).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return errMailActionObsolete
	}
	return nil
}

// activateEmailCode 创建验证码记录，并作废同一邮箱同一场景下的旧码。
//
// 两步放在同一个事务里：中间失败会留下「旧码已废、新码没建」的状态，
// 与我们要修的问题一模一样。
//
// # 顺序问题：只有最新的凭据能生效
//
// 较早的邮件送达后激活失败会进退避重试；期间用户又请求了新的验证码，
// 新邮件可能先一步送达并激活成功。此时旧动作若照常重试，「作废全部旧码」
// 会把刚生效的新码一起废掉，反而让更早的码活了下来。规则：本邮件入队
// **之后**激活的同类凭据一律视为更新，旧动作直接放弃
// （errMailActionSuperseded），以「用户最后一次请求」为准。
//
// 先后关系用凭据上的 MailID（发件箱记录 ID）判定，不用 created_at：
// 秒级精度下同一秒的两封信分不出先后；而且比较的是「已激活的凭据」，
// 与它有没有被用掉无关——较新的链接被用户用掉之后，旧邮件的延迟重试
// 仍然必须放弃，否则会把旧链接重新激活成有效凭据。
func (s *Services) activateEmailCode(row model.MailOutbox, token string) error {
	var p emailCodePayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	if p.TTLSeconds <= 0 {
		return errors.New("验证码缺少有效期参数")
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 这封信必须仍由本次领取持有：租约过期被别人接手、或期间被作废，
		// 都不该继续激活。
		if err := stillClaimed(tx, row.ID, token); err != nil {
			return err
		}

		// 找回密码的验证码只对「当前且已验证」的地址有意义。
		//
		// 地址被换掉之后（换绑事务可能与本动作交错），旧地址的验证码若照常
		// 激活，用户在找回页面填新邮箱也查不到它，反倒是旧邮箱持有人拿着
		// 一个「库里有效」的码——那正是清理之后被反向激活的那条路径。
		//
		// 加行锁与换绑串行：换绑同样锁这一行（见 ConfirmEmailChange），
		// 于是「查邮箱 → 插码」之间不可能插进一次换绑。
		if p.Scene == EmailSceneReset {
			var u model.User
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Where("lower(email) = ?", strings.ToLower(row.To)).
				First(&u).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errMailActionObsolete
			}
			if err != nil {
				return err
			}
			if !u.EmailVerified {
				return errMailActionObsolete
			}
			// 改密会递增 TokenVersion：排队期间用户改过密码的话，这个找回
			// 验证码必须作废——否则改密后旧码还能再改一次密码。
			// 判断放在用户行锁内，与改密事务（同样先锁这一行）只剩先后关系。
			//
			// 没有版本快照（升级前入队的邮件）：版本仍为初始值 1 说明这个
			// 账号从未改过密码，按原行为放行；否则无法证明期间没改过密码，
			// 一律作废——与重置链接同一策略，缺快照不能成为绕过口。
			if p.TokenVersion == nil {
				if u.TokenVersion > 1 {
					return errMailActionObsolete
				}
			} else if u.TokenVersion != *p.TokenVersion {
				return errMailActionObsolete
			}
		}

		// 幂等重放：激活成功但写终态失败时，这一步会按原参数再跑一遍。
		// 凭据仍在（同一摘要，或同一封信激活过——即便它已被用户用掉）
		// 就直接按成功处理，不重复建记录。
		var activated int64
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND code_hash = ? AND (mail_id = ? OR used_at IS NULL)",
				p.Email, p.Scene, p.CodeHash, row.ID).
			Count(&activated).Error; err != nil {
			return err
		}
		if activated > 0 {
			return nil
		}
		// 同一邮箱同一场景的激活必须串行。
		//
		// 两封不同的验证码邮件可能被两个实例分别领取：各自都查到「还没有更新的
		// 记录」，随后先后插入；若较早的那封最后提交，它的记录 ID 反而更大，
		// 而校验端按记录 ID 取最新——用户手里的**新码**就用不了了。
		// 锁住 (邮箱, 场景) 之后，插入顺序与邮件顺序一致。
		if err := s.lockAdvisory(tx, "emailcode:"+p.Email+":"+p.Scene); err != nil {
			return err
		}

		// 被更新者取代：本邮件之后激活的同类凭据胜出（含已使用的）。
		var newer int64
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND mail_id > ?", p.Email, p.Scene, row.ID).
			Count(&newer).Error; err != nil {
			return err
		}
		if newer > 0 {
			return errMailActionSuperseded
		}
		// 同一邮箱同一场景只保留最新一个可用验证码：否则用户连点几次后，
		// 前面几封邮件里的码也都还能用，等于扩大了攻击面。
		if err := tx.Model(&model.EmailCode{}).
			Where("email = ? AND scene = ? AND used_at IS NULL", p.Email, p.Scene).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.EmailCode{
			Email:    p.Email,
			Scene:    p.Scene,
			CodeHash: p.CodeHash,
			// 有效期从**现在**（送达时刻）起算。
			ExpireAt: time.Now().Add(time.Duration(p.TTLSeconds) * time.Second),
			IP:       p.IP,
			MailID:   row.ID,
		}).Error
	})
}

// activateResetToken 创建重置令牌，并作废该账号的旧令牌。
// 取代判定与幂等重放见 activateEmailCode 的说明——两者的竞态形态一致：
// 较早邮件的激活重试不得作废较新邮件刚生效的链接。
func (s *Services) activateResetToken(row model.MailOutbox, token string) error {
	var p resetLinkPayload
	if err := json.Unmarshal([]byte(row.Payload), &p); err != nil {
		return err
	}
	if p.TTLSeconds <= 0 {
		return errors.New("重置令牌缺少有效期参数")
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// 这封信必须仍由本次领取持有（同上）。
		if err := stillClaimed(tx, row.ID, token); err != nil {
			return err
		}

		// 收件地址必须仍是该账号**当前且已验证**的邮箱，且这一步要**锁住用户行**。
		//
		// 只查不锁是有洞的：本事务查到「还是旧邮箱」，换绑事务随后提交
		// （删掉旧令牌、把邮件标成失败），本事务最后才插入令牌——清理之后
		// 又出现一份可用的旧链接。两边都锁同一行之后只剩两种顺序：
		// 激活先完成（随后被换绑删掉），或换绑先完成（这里查到的邮箱已变，作废）。
		var u model.User
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, p.UserID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errMailActionObsolete
		}
		if err != nil {
			return err
		}
		if !u.EmailVerified || !strings.EqualFold(u.Email, row.To) {
			return errMailActionObsolete
		}
		// 改密会递增 TokenVersion：排队期间用户改过密码的话，这封信里的
		// 链接必须作废——否则用户（或拿到旧链接的人）能在改密之后再改一次，
		// 而改密的前提通常正是「账号可能已被他人控制」。
		//
		// 这里必须在**锁住用户行之后**判断：撤销令牌与插入令牌都以此为序，
		// 早一步判断会漏掉「改密事务正在提交」的窗口。
		//
		// 没有版本快照（升级前入队的邮件）时：版本仍为初始值 1 说明这个账号
		// 从未改过密码，链接不存在「改密后仍有效」的问题，按原行为放行；
		// 否则无法证明期间没改过密码，按作废处理（重新申请一次即可）。
		if p.TokenVersion == nil {
			if u.TokenVersion > 1 {
				return errMailActionObsolete
			}
		} else if u.TokenVersion != *p.TokenVersion {
			return errMailActionObsolete
		}
		// 幂等重放：同一令牌仍在（同一摘要，或同一封信激活过——即便
		// 已被用户用掉）直接按成功处理，不会因唯一索引冲突误判失败。
		var activated int64
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND token_hash = ? AND (mail_id = ? OR used_at IS NULL)",
				p.UserID, p.TokenHash, row.ID).
			Count(&activated).Error; err != nil {
			return err
		}
		if activated > 0 {
			return nil
		}
		// 被更新者取代：本邮件之后激活的令牌胜出（含已使用的）。
		var newer int64
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND mail_id > ?", p.UserID, row.ID).
			Count(&newer).Error; err != nil {
			return err
		}
		if newer > 0 {
			return errMailActionSuperseded
		}
		// 同一账号只保留一个有效令牌：避免多封邮件里的链接同时可用。
		if err := tx.Model(&model.PasswordResetToken{}).
			Where("user_id = ? AND used_at IS NULL", p.UserID).
			Update("used_at", time.Now()).Error; err != nil {
			return err
		}
		return tx.Create(&model.PasswordResetToken{
			UserID:    p.UserID,
			TokenHash: p.TokenHash,
			// 有效期从**现在**（送达时刻）起算。
			ExpireAt: time.Now().Add(time.Duration(p.TTLSeconds) * time.Second),
			IP:       p.IP,
			MailID:   row.ID,
		}).Error
	})
}
