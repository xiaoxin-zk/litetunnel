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

// RegisterInput 注册入参。
type RegisterInput struct {
	Username string
	Password string
	Email    string
	IP       string

	// 注册准入校验材料
	AgreedTerms   bool
	CaptchaTicket string
	CaptchaAnswer string
	// EmailCode 是邮箱一次性验证码。站点启用邮件后为必填。
	EmailCode string
}

// Register 创建用户并绑定默认分组。
//
// 注册是最容易被滥用的入口（批量注册、薅资源、拿隧道做跳板），
// 因此准入校验集中在这里，按「成本从低到高」短路，避免无谓的数据库查询。
func (s *Services) Register(in RegisterInput) (*model.User, error) {
	// 1. 注册开关：管理端可一键关闭注册
	if !s.Settings.Bool(KeyRegisterEnabled) {
		return nil, ErrRegisterClosed
	}
	// 2. 必须显式同意条款（前端勾选），这是禁止滥用条款生效的前提
	if !in.AgreedTerms {
		return nil, fmt.Errorf("%w: 请先阅读并同意服务条款与禁止滥用规定", ErrInvalidParam)
	}
	// 3. 验证码：由开关控制，默认开启
	if s.Settings.Bool(KeyRegisterCaptcha) {
		if !s.CheckCaptcha(in.CaptchaTicket, in.CaptchaAnswer) {
			return nil, ErrCaptchaInvalid
		}
	}

	username, email, err := validateNewUser(in.Username, in.Email, in.Password)
	if err != nil {
		return nil, err
	}
	in.Username, in.Email = username, email

	// 邮箱验证：站点启用邮件后，注册必须提供邮箱并通过一次性验证码。
	//
	// 为什么和邮件开关绑定而不是独立开关：没有邮件通道就无法验证邮箱真实性，
	// 此时强制要求验证码只会把用户挡在门外。启用邮件意味着运营方愿意承担
	// 验证成本，邮箱也就从「可选联系方式」升级为「身份凭证」。
	requireEmail := s.MailEnabled() && s.Settings.Bool(KeyRegisterRequireEmail)
	if requireEmail && in.Email == "" {
		return nil, ErrEmailRequired
	}

	// 4. 邮箱域名黑名单：拦住一次性邮箱批量注册
	if in.Email != "" && s.emailDomainBlocked(in.Email) {
		return nil, ErrEmailNotAllowed
	}

	domain := emailDomain(in.Email)
	trusted := s.isTrustedEmailDomain(domain)
	// 5. 白名单模式：开启后非白名单域名一律拒绝
	if s.Settings.Bool(KeyRegisterWhitelistOnly) && !trusted {
		return nil, ErrDomainNotTrusted
	}

	// 6. 频率限制。白名单域名可选择跳过：企业自有域名下员工批量注册属正常行为。
	skipLimits := trusted && s.Settings.Bool(KeyRegisterTrustedSkipLimits)
	if !skipLimits {
		// 单 IP 每日上限：拦住同一台机器批量注册
		if err := s.checkRegisterRate(in.IP); err != nil {
			return nil, err
		}
		// 单邮箱域名每日上限：拦住用同一邮箱服务商批量注册
		if err := s.checkDomainRate(domain); err != nil {
			return nil, err
		}
	}

	if err := s.checkUserUnique(in.Username, in.Email); err != nil {
		return nil, err
	}

	// 邮箱验证码放在最后校验，而且这里**只校验、不消费**。
	//
	// 必须等所有无副作用的校验都通过后再做，否则一次「用户名已占用」就会
	// 白白浪费用户一个验证码。消费则要和写用户放进同一个事务（见下）：
	// 分开做的话，写库失败或并发注册撞唯一索引时，注册没成功、验证码却已经
	// 失效了，用户只能重新收信。
	var codeRec *model.EmailCode
	if requireEmail {
		var cerr error
		codeRec, cerr = s.checkEmailCode(s.DB, in.Email, EmailSceneRegister, in.EmailCode)
		if cerr != nil {
			return nil, cerr
		}
	}

	// 哈希与密钥生成放在事务**之外**：bcrypt 是刻意设计成慢的，
	// 占着事务会拉长写锁持有时间。
	user, err := s.prepareNewUser(in.Username, in.Email, in.Password, in.IP, requireEmail)
	if err != nil {
		return nil, err
	}

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if codeRec != nil {
			if cerr := s.consumeEmailCode(tx, codeRec.ID); cerr != nil {
				return cerr
			}
		}
		return s.insertUserTx(tx, user)
	})
	if err != nil {
		return nil, err
	}
	return s.LoadUser(user.ID)
}

// validateNewUser 校验并清洗新账号资料。只读、无副作用。
//
// 抽出来是因为它有两个调用方（公开注册与管理端建号），而两者的**准入策略**
// 完全不同：注册要过注册开关、条款勾选、验证码、域名黑白名单与每日频率限制；
// 管理员建号是受信操作，不该受这些约束。校验与写入共用，准入各自处理。
func validateNewUser(username, email, password string) (string, string, error) {
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if len(username) < 3 || len(username) > 32 {
		return "", "", fmt.Errorf("%w: 用户名长度需为 3-32 个字符", ErrInvalidParam)
	}
	if !isSafeName(username) {
		return "", "", fmt.Errorf("%w: 用户名仅允许字母、数字、下划线", ErrInvalidParam)
	}
	if len(password) < 8 {
		return "", "", fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	if email != "" && !IsValidEmail(email) {
		return "", "", fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
	}
	return username, email, nil
}

// checkUserUnique 校验用户名与邮箱未被占用。
func (s *Services) checkUserUnique(username, email string) error {
	var exists int64
	if err := s.DB.Model(&model.User{}).Where("username = ?", username).Count(&exists).Error; err != nil {
		return err
	}
	if exists > 0 {
		return ErrUsernameTaken
	}
	if email == "" {
		return nil
	}
	// 邮箱唯一性：找回密码要靠邮箱定位账号，重复邮箱会让整个流程产生歧义。
	var emailExists int64
	if err := s.DB.Model(&model.User{}).Where("email = ?", email).Count(&emailExists).Error; err != nil {
		return err
	}
	if emailExists > 0 {
		return ErrEmailTaken
	}
	return nil
}

// insertUser 写入用户记录：密码哈希、初始 API Key、默认分组。
//
// ip 与 emailVerified 由调用方决定：公开注册会带上来源 IP 与「邮箱已验证」，
// 管理端建号两者都没有（管理员填的邮箱没有经过验证码校验，不该标成已验证）。
func (s *Services) insertUser(username, email, password, ip string, emailVerified bool) (*model.User, error) {
	user, err := s.prepareNewUser(username, email, password, ip, emailVerified)
	if err != nil {
		return nil, err
	}
	if err := s.insertUserTx(s.DB, user); err != nil {
		return nil, err
	}
	return s.LoadUser(user.ID)
}

// prepareNewUser 在事务**之外**完成哈希与密钥生成，返回待写入的用户对象。
//
// 拆出来是为了让调用方能把「写入用户」和别的操作（例如消费邮箱验证码）
// 放进同一个事务，而把 CPU 密集的哈希留在事务外。
func (s *Services) prepareNewUser(username, email, password, ip string, emailVerified bool) (*model.User, error) {
	hashed, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// 建号即生成 API Key：桌面客户端只用这一把凭据登录，
	// 用户不必再去控制台点一次「生成」，省掉一个容易卡住的步骤。
	apiKey, apiPrefix, apiHash, err := auth.GenerateAPIKey()
	if err != nil {
		return nil, err
	}
	apiEnc, err := auth.EncryptAPIKey(s.Cfg.APIKeyEncKey, apiKey)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	group := s.defaultGroup()
	user := &model.User{
		Username:        username,
		Email:           email,
		Password:        hashed,
		Nickname:        username,
		Status:          model.UserStatusActive,
		TrafficResetAt:  time.Now().AddDate(0, 1, 0),
		APIKeyHash:      apiHash,
		APIKeyPrefix:    apiPrefix,
		APIKeyEnc:       apiEnc,
		APIKeyCreatedAt: &now,
		RegisterIP:      truncate(ip, 64),
		EmailDomain:     truncate(emailDomain(email), 128),
		EmailVerified:   emailVerified,
	}
	if group != nil {
		user.GroupID = group.ID
	}
	return user, nil
}

// insertUserTx 在给定事务内写入用户记录。
//
// 唯一索引冲突在这里转成友好错误：并发注册时两个请求可能同时通过了
// 「用户名未占用」的检查，最终由数据库裁决。
func (s *Services) insertUserTx(db *gorm.DB, user *model.User) error {
	if err := db.Create(user).Error; err != nil {
		return ErrUsernameTaken
	}
	return nil
}

// emailDomainBlocked 判断邮箱域名是否命中黑名单。
//
// 支持两种写法：`example.com` 同时匹配 example.com 与其子域，
// 也容忍误写的 `@example.com`。
func (s *Services) emailDomainBlocked(email string) bool {
	raw := strings.TrimSpace(s.Settings.Get(KeyRegisterBlockDomains))
	if raw == "" {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
		if d == "" {
			continue
		}
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// emailDomain 从邮箱中取出小写域名，取不到时返回空串。
func emailDomain(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// isTrustedEmailDomain 判断邮箱域名是否命中白名单。
func (s *Services) isTrustedEmailDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return DomainInList(domain, ParseDomainList(s.Settings.Get(KeyRegisterAllowDomains)))
}

// checkDomainRate 限制单个邮箱域名在自然日内的注册数量。
//
// 与「单 IP 上限」互补：IP 上限挡不住换 IP 的批量注册，
// 但同一批注册往往共用同一个邮箱服务商，按域名计数能兜住。
func (s *Services) checkDomainRate(domain string) error {
	if domain == "" {
		return nil
	}
	limit := s.Settings.Int(KeyRegisterMaxPerDomain)
	if limit <= 0 {
		return nil
	}
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var n int64
	if err := s.DB.Model(&model.User{}).
		Where("email_domain = ? AND created_at >= ?", domain, dayStart).
		Count(&n).Error; err != nil {
		// 统计失败时放行，理由同 checkRegisterRate。
		return nil
	}
	if n >= int64(limit) {
		return ErrDomainRegisterLimited
	}
	return nil
}

// checkRegisterRate 限制单个 IP 在自然日内的注册数量。
//
// 按自然日而不是滑动窗口：口径与运营直觉一致，也便于在管理页解释。
func (s *Services) checkRegisterRate(ip string) error {
	limit := s.Settings.Int(KeyRegisterMaxPerIP)
	if limit <= 0 || ip == "" {
		return nil
	}
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var n int64
	if err := s.DB.Model(&model.User{}).
		Where("register_ip = ? AND created_at >= ?", ip, dayStart).
		Count(&n).Error; err != nil {
		// 统计失败时放行：宁可漏拦，也不要因为统计问题挡住正常用户。
		return nil
	}
	if n >= int64(limit) {
		return ErrRegisterLimited
	}
	return nil
}

// Authenticate 校验用户凭据。
func (s *Services) Authenticate(username, password, ip string) (*model.User, error) {
	username = strings.TrimSpace(username)
	var u model.User
	err := s.DB.Where("username = ?", username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 即使用户不存在也执行一次哈希校验，抹平响应时间差异，避免用户名枚举。
		auth.VerifyPassword("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin", password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if !auth.VerifyPassword(u.Password, password) {
		return nil, ErrBadCredentials
	}
	if u.Status != model.UserStatusActive {
		return nil, ErrAccountDisabled
	}

	now := time.Now()
	_ = s.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"last_login_at": now, "last_login_ip": ip}).Error

	return s.LoadUser(u.ID)
}

// LoadUser 载入用户并预加载分组。
func (s *Services) LoadUser(id uint) (*model.User, error) {
	var u model.User
	if err := s.DB.Preload("Group").First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.EnsureTrafficPeriod(&u)
	return &u, nil
}

// LoadUserByAPIKey 通过 API Key 明文定位用户。
func (s *Services) LoadUserByAPIKey(plain string) (*model.User, error) {
	if plain == "" {
		return nil, ErrNotFound
	}
	hash := auth.HashAPIKey(plain)
	var u model.User
	if err := s.DB.Preload("Group").Where("api_key_hash = ?", hash).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if u.Status != model.UserStatusActive {
		return nil, ErrAccountDisabled
	}
	s.EnsureTrafficPeriod(&u)
	return &u, nil
}

// LoadUserByClientSecret 通过客户端接入凭据定位用户。
//
// 桌面客户端只持有该凭据（而非账号密码），既避免本地留存口令，
// 又支持在服务端单独吊销。
func (s *Services) LoadUserByClientSecret(secret string) (*model.User, error) {
	if secret == "" {
		return nil, ErrNotFound
	}
	var u model.User
	if err := s.DB.Preload("Group").Where("client_secret = ?", secret).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if u.Status != model.UserStatusActive {
		return nil, ErrAccountDisabled
	}
	s.EnsureTrafficPeriod(&u)
	return &u, nil
}

// RotateAPIKey 重置 API Key，返回仅此一次可见的明文。
func (s *Services) RotateAPIKey(userID uint) (plain, prefix string, err error) {
	plain, prefix, hash, err := auth.GenerateAPIKey()
	if err != nil {
		return "", "", err
	}
	enc, err := auth.EncryptAPIKey(s.Cfg.APIKeyEncKey, plain)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	err = s.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"api_key_hash":       hash,
		"api_key_prefix":     prefix,
		"api_key_enc":        enc,
		"api_key_created_at": now,
	}).Error
	if err != nil {
		return "", "", err
	}
	return plain, prefix, nil
}

// RevealAPIKey 解密回显当前 API Key（供控制台复制）。
func (s *Services) RevealAPIKey(u *model.User) (string, error) {
	if u.APIKeyEnc == "" {
		return "", ErrNotFound
	}
	return auth.DecryptAPIKey(s.Cfg.APIKeyEncKey, u.APIKeyEnc)
}

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
		email := strings.TrimSpace(*in.Email)
		if email != "" && !IsValidEmail(email) {
			return nil, fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
		}
		updates["email"] = email
	}

	if len(updates) == 0 {
		return u, nil
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		// 唯一索引冲突（并发改名）同样按占用处理。
		return nil, ErrUsernameTaken
	}
	if renamed {
		// 会话表里的用户名仅用于后台展示，改名后同步，避免显示旧值。
		_ = s.DB.Model(&model.ClientSession{}).Where("user_id = ?", userID).
			Update("username", updates["username"]).Error
	}
	return s.LoadUser(userID)
}

// IsValidEmail 做基础格式校验：恰好一个 @，域名部分为合法主机名。
//
// 不做完整 RFC 5322 校验——邮箱的真实性只能靠验证邮件确认，
// 而本项目暂未实现邮件发送，因此这里只拦截明显错误的输入。
func IsValidEmail(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if local == "" || strings.ContainsAny(local, " \t\r\n") {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return isValidHostname(domain)
}

// UpdatePassword 修改密码。
//
// 改密后自增 TokenVersion，使此前签发的所有令牌立即失效——
// JWT 无状态，这是让「改密即全端下线」成立的唯一办法。
func (s *Services) UpdatePassword(userID uint, oldPwd, newPwd string) error {
	var u model.User
	if err := s.DB.First(&u, userID).Error; err != nil {
		return ErrNotFound
	}
	if !auth.VerifyPassword(u.Password, oldPwd) {
		return fmt.Errorf("%w: 原密码不正确", ErrInvalidParam)
	}
	if len(newPwd) < 8 {
		return fmt.Errorf("%w: 新密码长度不得少于 8 位", ErrInvalidParam)
	}
	if newPwd == oldPwd {
		return fmt.Errorf("%w: 新密码不能与原密码相同", ErrInvalidParam)
	}
	hashed, err := auth.HashPassword(newPwd)
	if err != nil {
		return err
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"password":      hashed,
		"token_version": gorm.Expr("token_version + 1"),
	}).Error; err != nil {
		return err
	}
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	return nil
}

// DeleteAccount 用户注销自己的账号。
//
// 需要提供登录密码二次确认：注销不可恢复，必须防止令牌被盗后被恶意注销。
// 关联数据一并清理，避免留下悬空记录。
func (s *Services) DeleteAccount(userID uint, password string) error {
	var u model.User
	if err := s.DB.First(&u, userID).Error; err != nil {
		return ErrNotFound
	}
	if !auth.VerifyPassword(u.Password, password) {
		return fmt.Errorf("%w: 登录密码不正确", ErrInvalidParam)
	}

	// 与「给自己建隧道」互斥（见 userLock）：只把端口读取放进事务还不够，
	// READ COMMITTED 下在端口查询之后提交的新隧道仍可能被删掉而漏出回收清单。
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	// 端口在**事务内**读取，删完之后再用（见下面 closePorts 的位置）。
	var ports []portProto

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var tunnels []model.Tunnel
		if err := tx.Where("user_id = ? AND remote_port > 0", userID).Find(&tunnels).Error; err != nil {
			return err
		}
		ports = portsOfTunnels(tunnels)
		if err := tx.Where("user_id = ?", userID).Delete(&model.Tunnel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.TrafficDaily{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.ClientSession{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.PasswordResetToken{}).Error; err != nil {
			return err
		}
		// 兑换流水与登录日志保留：它们属于审计数据，删除会让风控出现盲区。
		return tx.Delete(&model.User{}, userID).Error
	})
	if err != nil {
		return err
	}

	// ---- 事务提交之后再做这些 ----
	//
	// 内存清理放进事务回调里的话，事务一旦失败就会出现「缓存已清、库里还在」
	// 的不一致；多连接数据库上还可能与并发回调抢跑。
	// 注销也是管理路径的直写：先递增版本号让在途的后台刷新让路。
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(userID, false)
	s.Runtime.SetUserBlocked(userID, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
	// 会话同样要清：数据库里的会话行已经随事务删除，但插件热路径
	// （onNewUserConn）查的是内存会话表。账号都注销了还能继续建新连接，
	// 是最不该出现的一种。
	s.Runtime.DropUserSessions(userID)

	// 隧道没了，主机防火墙上的放行规则也要收回。
	s.closePorts(ports)
	return nil
}

// isSafeName 限制用户名可用字符，避免其进入 frp 的 proxy 名前缀时引入注入风险。
func isSafeName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
		default:
			return false
		}
	}
	return true
}

// IsSafeName 导出给处理器复用。
func IsSafeName(s string) bool { return isSafeName(s) }
