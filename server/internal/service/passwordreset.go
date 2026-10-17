package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

const (
	// resetTokenTTL 是重置链接的有效期。过长会放大邮件被转发带来的风险。
	resetTokenTTL = 30 * time.Minute
	// resetTokenBytes 是令牌的随机字节数，256 位熵足以抵抗暴力猜测。
	resetTokenBytes = 32
)

// ErrMailDisabled 表示站点未配置邮件服务。
// 这是配置问题，与账号是否存在无关，因此可以安全地对外暴露。
var ErrMailDisabled = errors.New("站点未配置邮件服务，请联系管理员重置密码")

// ErrMailQueueFull 表示发信队列已满，这封信没有投出去。
//
// 与 ErrMailDisabled 一样属于「与账号是否存在无关」的故障，
// 可以安全地对外暴露：它由服务端负载决定，不携带任何账号信息。
var ErrMailQueueFull = errors.New("邮件发送队列繁忙，请稍后重试")

// ErrFirewallUnavailable 表示防火墙总开关开着，但宿主机 helper 不可用。
//
// 与「防火墙未启用」必须区分：后者是「本来就不该动规则」，返回 nil 是对的；
// 前者是「该动但动不了」，必须作为失败上报，否则这次操作既没生效、
// 也不会进入重试队列。
var ErrFirewallUnavailable = errors.New("宿主机防火墙 helper 不可用")

// 重置令牌相关错误。
var (
	ErrResetTokenInvalid = errors.New("重置链接无效，请重新申请")
	ErrResetTokenExpired = errors.New("重置链接已过期，请重新申请")
)

// RequestPasswordReset 发起找回密码。account 可以是用户名或邮箱。
//
// 安全要求：无论账号是否存在、是否填写邮箱、是否被禁用，
// 本方法都返回 nil 且耗时基本一致——否则该接口会退化成账号枚举工具。
// 真正的失败原因只写日志。
func (s *Services) RequestPasswordReset(account, ip, baseURL string) error {
	if !s.MailEnabled() {
		return ErrMailDisabled
	}

	account = strings.TrimSpace(account)
	if account == "" {
		return nil
	}

	// 没有对外地址就生成不出可用的链接（拼出来会是相对路径），直接静默返回。
	//
	// 这里是第二道防线：调用方本来就会检查配置，但凭据链接的地址只能来自
	// 服务端配置，不能靠「调用方记得传对」来保证。
	if strings.TrimSpace(baseURL) == "" {
		log.Printf("[reset] 缺少对外地址，无法生成重置链接，本次不发信")
		return nil
	}

	u, err := s.findUserByAccount(account)
	if err != nil || u.Email == "" || !u.EmailVerified || u.Status != model.UserStatusActive {
		// 静默返回，不区分具体原因。
		//
		// 未验证的邮箱一律不发信：它只可能是「邮件关着时随手填的联系方式」，
		// 从没证明过归属。邮件开关重新打开后若仍按它发重置链接，等于把一个
		// 随手填的地址变成了恢复入口——而那可能就是别人的邮箱。
		log.Printf("[reset] 找回密码请求未命中有效账号（输入长度 %d）", len(account))
		return nil
	}

	plain, hash, err := newResetToken()
	if err != nil {
		log.Printf("[reset] 生成令牌失败: %v", err)
		return nil
	}

	siteName := s.Settings.Get(KeySiteName)
	if siteName == "" {
		siteName = "LiteTunnel"
	}
	link := strings.TrimRight(baseURL, "/") + "/reset-password?token=" + plain
	subject := fmt.Sprintf("【%s】重置登录密码", siteName)
	body := resetMailBody(siteName, u.Username, link, int(resetTokenTTL.Minutes()))

	// 只写发件箱，**不建令牌记录**：令牌等这封信真的送达之后再创建
	// （见 applyMailAction）。
	//
	// 这样「旧链接失效」与「新链接到手」是同一件事的两个面：投递失败时
	// 用户手上的旧链接依然可用，而不是旧的全废、新的又没收到。
	//
	// 投递走异步队列：SMTP 往返可能耗时数秒，
	// 若同步发送会让「账号存在」的响应明显变慢，从而泄露账号是否存在。
	//
	// 入队失败只记日志、对外仍然返回成功：这里已经走完了「账号存在 + 有效」
	// 的判断，此时返回错误会让「已注册 + 入队失败」与「未注册」产生可区分的
	// 响应，接口就退化成账号枚举工具了。这是刻意的取舍——宁可用户多点一次
	// 「重新发送」，也不给枚举留口子。
	// 入队时按收件地址复核额度（冷却 + 每日上限），复核与写入在同一个事务里。
	//
	// 这条路径原先只有按 IP 的令牌桶：分布式来源可以轮流换 IP，对同一个
	// 邮箱持续排队重置邮件、挤占发件箱。复核放在写入**之前**，超限时一条
	// 记录都不留——否则失败记录会继续占额度，一次突发就能把当日额度耗光。
	//
	// 入队失败只记日志、对外仍然返回成功：这里已经走完了「账号存在 + 有效」
	// 的判断，此时返回错误会让「已注册 + 入队失败」与「未注册」产生可区分的
	// 响应，接口就退化成账号枚举工具了。这是刻意的取舍——宁可用户多点一次
	// 「重新发送」，也不给枚举留口子。
	tokenVersion := u.TokenVersion
	if _, err := s.enqueueMail(u.Email, subject, body, model.MailKindResetLink, resetLinkPayload{
		UserID:    u.ID,
		TokenHash: hash,
		// 存 TTL 而不是绝对时间：有效期从**送达时刻**起算，否则排队或重试
		// 拖久了，用户点开链接时它已经过期。
		TTLSeconds: int(resetTokenTTL.Seconds()),
		IP:         truncate(ip, 64),
		// 入队时的令牌版本：送达后激活时要拿它复核「期间有没有改过密码」。
		TokenVersion: &tokenVersion,
	}, mailQuota{cooldown: resetLinkCooldown, dailyLimit: resetLinkDailyPerEmail}); err != nil {
		log.Printf("[reset] 重置邮件未发出（账号 %d），原有令牌未受影响: %v", u.ID, err)
		return nil
	}
	return nil
}

// 找回密码链接按收件地址的限流参数。
//
// 与验证码的限制分开：链接是「点一下就重置」的凭据，被刷的后果更重
// （收件箱被灌满、真正的重置信被埋掉），所以日上限更紧。
const (
	resetLinkCooldown      = 60 * time.Second
	resetLinkDailyPerEmail = 5
)

// ResetPassword 使用令牌重置密码。
//
// 成功后自增 TokenVersion 并吊销客户端接入凭据：
// 重置密码通常意味着账号可能已被他人控制，必须把攻击者踢下线。
func (s *Services) ResetPassword(token, newPassword, ip string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrResetTokenInvalid
	}
	if len(newPassword) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}

	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var tok model.PasswordResetToken
	err := s.DB.Where("token_hash = ?", hash).First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrResetTokenInvalid
	}
	if err != nil {
		return err
	}
	if tok.UsedAt != nil {
		return ErrResetTokenInvalid
	}
	if time.Now().After(tok.ExpireAt) {
		return ErrResetTokenExpired
	}

	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	newSecret, err := randomHex(32)
	if err != nil {
		return err
	}

	now := time.Now()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// 条件更新：并发下只有一个请求能把 used_at 从 NULL 改成功，
		// 从而保证令牌只能被使用一次。
		res := tx.Model(&model.PasswordResetToken{}).
			Where("id = ? AND used_at IS NULL", tok.ID).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrResetTokenInvalid
		}

		// 必须检查影响行数：账号可能在邮件送达之后被管理员删除，
		// 此时这条更新一行都改不到。不看的话事务照样提交（令牌被标记为
		// 已用），接口返回「重置成功」——而根本没有账号被改动。
		// 返回令牌无效让整个事务回滚，令牌也不会被白白消费。
		res = tx.Model(&model.User{}).Where("id = ?", tok.UserID).Updates(map[string]any{
			"password":      hashed,
			"token_version": gorm.Expr("token_version + 1"),
			// 客户端凭据一并吊销，避免已泄露的 frpc 配置继续可用。
			"client_secret": newSecret,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrResetTokenInvalid
		}

		// 该用户已建立的客户端会话全部标记离线，迫使其重新认证。
		return tx.Model(&model.ClientSession{}).
			Where("user_id = ?", tok.UserID).
			Update("online", false).Error
	})
	if err != nil {
		return err
	}

	// 走公共收尾：除了失效身份缓存，还要清掉**本机内存里的 frpc 会话**。
	//
	// 只把数据库会话标成离线是不够的：插件热路径命中内存会话后只看配额就放行，
	// 不会去读数据库，于是旧 frpc 仍能继续建立新连接——而「重置密码」的前提
	// 恰恰是账号可能已被他人控制。另一台实例的会话由会话准入快照在 Ping 时
	// 复核数据库会话状态来收敛（见 RefreshSessionGuard）。
	s.finishPasswordReset(tok.UserID, ip)
	log.Printf("[reset] 用户 %d 已通过邮件重置密码（来源 %s）", tok.UserID, ip)
	return nil
}

// ResetPasswordByOldPassword 用旧密码证明身份后重置密码。
//
// 用于「站点未启用邮件」的部署：没有发信通道就走不了验证码，
// 但用户依然应当能自助重置，而不是只能找管理员。
//
// 安全性等价于一次登录（都要校验密码），因此必须套用与登录**完全相同**的
// IP 限流与账号锁定策略——否则它会立刻变成一条绕过锁定的旁路：
// 攻击者被登录接口锁住后，改打这个接口继续撞库。
func (s *Services) ResetPasswordByOldPassword(account, oldPassword, newPassword, ip string) error {
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	u, err := s.findUserByAccount(account)
	if err != nil {
		// 不区分「账号不存在」与「密码错误」，避免把接口变成账号枚举工具。
		return ErrBadCredentials
	}
	if u.Status != model.UserStatusActive {
		return ErrAccountDisabled
	}
	if !auth.VerifyPassword(u.Password, oldPassword) {
		return ErrBadCredentials
	}
	// 新旧密码相同没有意义，且会让用户误以为改成功了。
	if auth.VerifyPassword(u.Password, newPassword) {
		return fmt.Errorf("%w: 新密码不能与当前密码相同", ErrInvalidParam)
	}
	return s.applyPasswordReset(u.ID, newPassword, ip)
}

// ResetPasswordByEmailCode 用邮箱一次性验证码重置密码。
//
// 用于「站点已启用邮件」的部署。验证码在 applyPasswordReset 之前消费，
// 校验通过即失效，无法重放。
func (s *Services) ResetPasswordByEmailCode(account, emailCode, newPassword, ip string) error {
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	u, err := s.findUserByAccount(account)
	if err != nil {
		// 统一返回「验证码不正确」，不透露账号是否存在。
		return ErrEmailCodeWrong
	}
	if u.Status != model.UserStatusActive {
		return ErrAccountDisabled
	}
	if u.Email == "" {
		return fmt.Errorf("%w: 该账号未绑定邮箱，无法通过邮箱重置，请联系管理员", ErrInvalidParam)
	}
	if !u.EmailVerified {
		// 未验证的邮箱从来没证明过归属，不能当作恢复凭据。
		// 提示与「验证码不正确」一致：这里不该透露更多账号细节。
		return ErrEmailCodeWrong
	}
	// 先校验验证码，**再**做哈希与密钥生成。
	//
	// 顺序很重要：preparePasswordReset 里的 bcrypt 是刻意设计成慢的（防离线
	// 爆破），放在校验之前的话，任何一个错误验证码的请求都会消耗这段 CPU
	// ——接口虽有按 IP 限流，但分布式来源仍能把它放大成 CPU 耗尽。
	//
	// 校验本身是只读的（失败计数除外），把它的结果先拿到手，下面的哈希与
	// 事务都只在验证码正确时才发生。
	rec, err := s.checkEmailCode(s.DB, u.Email, EmailSceneReset, emailCode)
	if err != nil {
		return err
	}

	hashed, newSecret, err := s.preparePasswordReset(newPassword)
	if err != nil {
		return err
	}

	// 再把「消费验证码 + 更新密码」放进**同一个事务**。
	//
	// 顺序不能是「先消费、再另起一个事务改密码」：那样密码更新失败时，
	// 验证码已经被标记为已使用——用户手里的码废了、密码却没改，只能等冷却后
	// 重新申请。放进同一事务后，失败会一并回滚，验证码仍然可用。
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.consumeEmailCode(tx, rec.ID); err != nil {
			return err
		}
		return s.applyPasswordResetTx(tx, u.ID, hashed, newSecret)
	})
	if err != nil {
		return err
	}

	s.finishPasswordReset(u.ID, ip)
	return nil
}

// validateNewPassword 统一新密码的强度校验。
func validateNewPassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	if len(p) > 128 {
		return fmt.Errorf("%w: 密码长度不得超过 128 位", ErrInvalidParam)
	}
	return nil
}

// applyPasswordReset 执行重置的公共部分。
//
// 三件事必须一起做，缺任何一件都会留下「旧凭据仍然可用」的窗口：
//  1. 自增令牌版本 → 所有已签发的 JWT 立即失效（改密即全端下线）
//  2. 轮换 client_secret → 已下发的 frpc 配置立即失效
//  3. 客户端会话标记离线 → 迫使客户端重新认证
//
// 注意这里**不动** API Key：它与登录会话是两套独立的吊销通道，
// 需要用户在控制台显式重置。这与 GitHub PAT / AWS Access Key 的语义一致。
func (s *Services) applyPasswordReset(userID uint, newPassword, ip string) error {
	hashed, newSecret, err := s.preparePasswordReset(newPassword)
	if err != nil {
		return err
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		return s.applyPasswordResetTx(tx, userID, hashed, newSecret)
	}); err != nil {
		return err
	}

	s.finishPasswordReset(userID, ip)
	return nil
}

// preparePasswordReset 在事务**之外**完成哈希与密钥生成。
//
// 放外面是有意的：HashPassword 是 CPU 密集操作，占着事务会拉长写锁持有时间。
func (s *Services) preparePasswordReset(newPassword string) (hashed, newSecret string, err error) {
	hashed, err = auth.HashPassword(newPassword)
	if err != nil {
		return "", "", err
	}
	newSecret, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	return hashed, newSecret, nil
}

// applyPasswordResetTx 在给定事务内完成重置的数据库部分。
//
// 拆出来是为了让调用方能把它和别的操作（例如消费验证码）放进同一个事务。
func (s *Services) applyPasswordResetTx(tx *gorm.DB, userID uint, hashed, newSecret string) error {
	// 先锁住用户行：撤销重置令牌与「送达后激活」都以此为序（见
	// activateResetToken），否则撤销与激活交错时仍会留下一条可用令牌。
	var u model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 账号可能在邮件发出之后被管理员删除：返回凭据无效让事务整体回滚，
			// 验证码/令牌不会被白白消费。
			return ErrResetTokenInvalid
		}
		return err
	}

	// 影响行数为 0 说明账号已不存在（与上面的 First 重复，但保留一道保险）。
	// 不看的话：验证码/令牌已被标记为使用、接口返回「重置成功」，
	// 而密码根本没有更新——用户以为账号还在、密码已重置。
	// 返回错误让事务整体回滚，调用方按「凭据无效」处理。
	res := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
		"client_secret": newSecret,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrResetTokenInvalid
	}
	if err := revokeClientSessionsTx(tx, userID); err != nil {
		return err
	}
	return revokePasswordResetTx(tx, userID, u.Email)
}

// revokePasswordResetTx 撤销「尚未使用」的重置令牌，并作废排队中的重置邮件。
//
// 改密之后旧链接必须立刻失效：ResetPassword 校验的是令牌自己的 used_at 与
// expire_at，不看 TokenVersion，所以不显式撤销的话，改密前发出的链接在
// 有效期内还能再改一次密码。
//
// 排队中的邮件更隐蔽——令牌是**送达时**才创建的（见 activateResetToken），
// 这里撤销时它还不存在。所以两条一起做：能撤销的撤销，还没生成的靠
// 载荷里的 TokenVersion 在激活时拦下（见 resetLinkPayload.TokenVersion）。
//
// 调用方必须已在同一事务里锁住用户行：activateResetToken 同样先锁这一行，
// 于是两边只剩先后关系，不会出现「撤销之后又插入一条可用令牌」。
func revokePasswordResetTx(tx *gorm.DB, userID uint, email string) error {
	if err := tx.Model(&model.PasswordResetToken{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Update("used_at", time.Now()).Error; err != nil {
		return err
	}
	if email == "" {
		return nil
	}
	// 只动「重置链接」这一类，且只动还没走完的：已送达的邮件记录保留，
	// 它对应的令牌已在上面撤销，用户点开只会看到「链接无效」。
	return tx.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ? AND status IN ?",
			strings.ToLower(email), model.MailKindResetLink,
			[]string{model.MailPending, model.MailSending, model.MailActivating}).
		Updates(map[string]any{
			"status":      model.MailFailed,
			"claim_token": "",
			"body":        "",
			"payload":     "",
			"last_err":    "密码已修改，重置邮件作废",
		}).Error
}

// finishPasswordReset 做提交之后的收尾：内存态同步与日志。
//
// 必须在事务**提交之后**调用：提交前清会话的话，事务一旦回滚，
// 内存里的会话已经没了而密码没变——用户会莫名其妙掉线。
func (s *Services) finishPasswordReset(userID uint, ip string) {
	// 数据库会话置为离线还不够：插件热路径查的是**内存**会话表，
	// 命中后只校验配额就放行，不会去读数据库。不一起清掉的话，
	// 重置密码后已登录的 frpc 仍能继续接受新连接——而重置密码的前提
	// 恰恰是「账号可能已被他人控制」。
	s.Runtime.DropUserSessions(userID)

	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	log.Printf("[reset] 用户 %d 已重置密码（来源 %s）", userID, ip)
}

// findUserByAccount 支持用用户名或邮箱定位账号。
func (s *Services) findUserByAccount(account string) (*model.User, error) {
	var u model.User
	// 邮箱用 lower() 比较：老数据里可能有大小写混写的地址，
	// 而用户在找回页面填的几乎总是小写。
	err := s.DB.Where("username = ? OR lower(email) = ?", account, strings.ToLower(account)).
		First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func newResetToken() (plain, hash string, err error) {
	buf := make([]byte, resetTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	plain = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(sum[:]), nil
}

// resetMailBody 生成重置邮件正文。
//
// 刻意采用内联样式的简单 HTML：邮件客户端对外部样式表支持极差。
func resetMailBody(siteName, username, link string, ttlMinutes int) string {
	return fmt.Sprintf(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:28px;">
    <h2 style="margin:0 0 8px;font-size:18px;color:#1f2937;">重置登录密码</h2>
    <p style="color:#4b5563;line-height:1.8;margin:0 0 18px;">
      你好 %s，我们收到了 %s 的密码重置请求。<br>
      点击下面的按钮设置新密码，链接 %d 分钟内有效。
    </p>
    <p style="margin:0 0 22px;">
      <a href="%s" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
         padding:11px 22px;border-radius:9px;font-weight:500;">设置新密码</a>
    </p>
    <p style="color:#6b7280;font-size:13px;line-height:1.8;margin:0 0 14px;">
      按钮无法点击时，请复制下面的链接到浏览器打开：
    </p>
    <p style="word-break:break-all;color:#2563eb;font-size:13px;margin:0 0 18px;">%s</p>
    <hr style="border:none;border-top:1px solid #eef1f6;margin:18px 0;">
    <p style="color:#9ca3af;font-size:12px;line-height:1.8;margin:0;">
      如果这不是你本人的操作，请忽略本邮件，你的密码不会发生变化。<br>
      为保障账号安全，重置成功后所有已登录设备都将下线。
    </p>
  </div>
</body></html>`, username, siteName, ttlMinutes, link, link)
}
