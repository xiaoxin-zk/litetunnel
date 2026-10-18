package service

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
		if err := s.checkRegisterRate(s.DB, in.IP, false); err != nil {
			return nil, err
		}
		// 单邮箱域名每日上限：拦住用同一邮箱服务商批量注册
		if err := s.checkDomainRate(s.DB, domain, false); err != nil {
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
		if !skipLimits {
			// 额度预留：先按**固定顺序**锁住额度键，再统计，再写入。
			//
			// 锁必须赶在统计之前拿到。PostgreSQL 默认 READ COMMITTED 下，
			// 「先数、后插」的两个事务看不到彼此尚未提交的行——两边都会读到
			// 「还剩最后一个名额」并各自提交，最终超额。锁住同一个键之后，
			// 后一个事务要等前一个提交，随后的统计才看得到那一条。
			//
			// 顺序固定（排序后再取）是为了避免两个并发注册互相等对方的键。
			keys := make([]string, 0, 2)
			if in.IP != "" {
				keys = append(keys, "register:ip:"+in.IP)
			}
			if domain != "" {
				keys = append(keys, "register:domain:"+domain)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := s.lockRegisterQuota(tx, k); err != nil {
					return err
				}
			}
			if err := s.checkRegisterRate(tx, in.IP, false); err != nil {
				return err
			}
			if err := s.checkDomainRate(tx, domain, false); err != nil {
				return err
			}
		}
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
	// 邮箱统一小写存库：找回密码按邮箱定位账号，大小写混写会让「同一个地址」
	// 在库里变成两条不同记录（老数据仍有混写，查询侧统一用 lower(email) 兜住）。
	email = strings.ToLower(strings.TrimSpace(email))
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
	taken, err := s.emailTaken(email, 0)
	if err != nil {
		return err
	}
	if taken {
		return ErrEmailTaken
	}
	return nil
}

// emailTaken 判断邮箱是否已被其他账号占用（大小写不敏感）。
//
// 必须用 lower(email) 比较：早期版本把邮箱按用户输入原样存库，老数据里
// 可能存在大小写混写的地址；而数据库上的唯一索引是「尽力而为」的
// （历史重复时建不起来），这条检查就是它缺席时的唯一防线。
// exceptID 为 0 表示「不与任何账号比较」（注册场景）。
func (s *Services) emailTaken(email string, exceptID uint) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false, nil
	}
	q := s.DB.Model(&model.User{}).Where("lower(email) = ?", email)
	if exceptID != 0 {
		q = q.Where("id <> ?", exceptID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
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
		// 只有唯一约束冲突才映射成「已被占用」：数据库故障、字段超长之类的
		// 错误必须原样返回，否则用户会得到一个与事实不符的结论（去换用户名），
		// 而真实原因是服务端故障，怎么改都注册不上。
		if isUniqueConflict(err) {
			if strings.Contains(strings.ToLower(err.Error()), "email") {
				return ErrEmailTaken
			}
			return ErrUsernameTaken
		}
		return err
	}
	return nil
}

// isUniqueConflict 判断错误是否来自唯一约束冲突。
//
// 两个驱动的报错文本不同：SQLite 是 UNIQUE constraint failed: ...，
// PostgreSQL 是 duplicate key value violates unique constraint "..."
func isUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
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
//
// db 由调用方给：前置检查用主连接，事务内复核必须用 tx——
// SQLite 只开一个连接，事务里再走 s.DB 会自己把自己等死。
//
// inclusive 表示统计**包含刚写入的那条**记录，见 overLimit。
func (s *Services) checkDomainRate(db *gorm.DB, domain string, inclusive bool) error {
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
	if err := db.Model(&model.User{}).
		Where("email_domain = ? AND created_at >= ?", domain, dayStart).
		Count(&n).Error; err != nil {
		// 统计失败时放行，理由同 checkRegisterRate。
		return nil
	}
	if overLimit(n, limit, inclusive) {
		return ErrDomainRegisterLimited
	}
	return nil
}

// lockRegisterQuota 在事务内按「额度键」加锁，把同键的并发注册串行化。
//
// PostgreSQL 用事务级 advisory lock：键相同的事务排队，后一个拿到锁时前一个
// 已经提交，随后的统计才看得到它。SQLite 不需要——store.Open 里连接池只有
// 一个连接，事务天然串行。
//
// hashtext 有 32 位碰撞可能：撞了只是让两组无关的注册多串行一会儿，
// 不影响正确性。
func (s *Services) lockRegisterQuota(tx *gorm.DB, key string) error {
	return s.lockAdvisory(tx, key)
}

// overLimit 判断计数是否已超出注册上限。
//
// inclusive 表示这次统计把**刚写入的这条记录**也算进去了：预留之后，
// 恰好等于上限是正常的，只有超过才该回滚。两个口径混用会让每天都多放
// （或误杀）恰好一条记录——这种偏差只看日志根本发现不了。
func overLimit(n int64, limit int, inclusive bool) bool {
	if limit <= 0 {
		return false
	}
	if inclusive {
		return n > int64(limit)
	}
	return n >= int64(limit)
}

// checkRegisterRate 限制单个 IP 在自然日内的注册数量。
//
// 按自然日而不是滑动窗口：口径与运营直觉一致，也便于在管理页解释。
// db / inclusive 的含义见 checkDomainRate。
func (s *Services) checkRegisterRate(db *gorm.DB, ip string, inclusive bool) error {
	limit := s.Settings.Int(KeyRegisterMaxPerIP)
	if limit <= 0 || ip == "" {
		return nil
	}
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var n int64
	if err := db.Model(&model.User{}).
		Where("register_ip = ? AND created_at >= ?", ip, dayStart).
		Count(&n).Error; err != nil {
		// 统计失败时放行：宁可漏拦，也不要因为统计问题挡住正常用户。
		return nil
	}
	if overLimit(n, limit, inclusive) {
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

	// 与重置客户端凭据同一套：用户锁 + 行锁串行并发轮换，并校验 RowsAffected。
	// 否则两个请求都可能返回「成功」，库里却只有最后写入的一份密钥；用户不
	// 存在时也会静默成功。
	lock := s.userLock(userID)
	lock.Lock()
	defer lock.Unlock()

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var cur model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").First(&cur, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		res := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
			"api_key_hash":       hash,
			"api_key_prefix":     prefix,
			"api_key_enc":        enc,
			"api_key_created_at": now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
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
