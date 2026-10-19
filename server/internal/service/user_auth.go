package service

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type RegisterInput struct {
	Username string
	Password string
	Email    string
	IP       string

	AgreedTerms   bool
	CaptchaTicket string
	CaptchaAnswer string
	EmailCode     string
}

func (s *Services) Register(in RegisterInput) (*model.User, error) {
	if !s.Settings.Bool(KeyRegisterEnabled) {
		return nil, ErrRegisterClosed
	}
	if !in.AgreedTerms {
		return nil, fmt.Errorf("%w: 请先阅读并同意服务条款与禁止滥用规定", ErrInvalidParam)
	}
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

	requireEmail := s.MailEnabled() && s.Settings.Bool(KeyRegisterRequireEmail)
	if requireEmail && in.Email == "" {
		return nil, ErrEmailRequired
	}

	verdict := s.emailDomainVerdictFor(in.Email)
	if verdict.Reject != nil {
		return nil, verdict.Reject
	}

	domain := RegistrationDomainKey(in.Email)
	trusted := s.isTrustedEmailDomain(emailDomain(in.Email))

	skipLimits := trusted && s.Settings.Bool(KeyRegisterTrustedSkipLimits)
	if !skipLimits {
		if err := s.checkRegisterRate(s.DB, in.IP, false); err != nil {
			return nil, err
		}
		if err := s.checkDomainRate(s.DB, domain, false); err != nil {
			return nil, err
		}
	}

	if verdict.Quota > 0 {
		if err := s.checkNonWhitelistQuota(s.DB, domain, verdict.Quota); err != nil {
			return nil, err
		}
	}

	if err := s.checkUserUnique(in.Username, in.Email); err != nil {
		return nil, err
	}

	var codeRec *model.EmailCode
	if requireEmail {
		var cerr error
		codeRec, cerr = s.checkEmailCode(s.DB, in.Email, EmailSceneRegister, in.EmailCode)
		if cerr != nil {
			return nil, cerr
		}
	}

	user, err := s.prepareNewUser(in.Username, in.Email, in.Password, in.IP, requireEmail)
	if err != nil {
		return nil, err
	}

	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if !skipLimits {
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
		if verdict.Quota > 0 {
			if err := s.checkNonWhitelistQuota(tx, domain, verdict.Quota); err != nil {
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

func validateNewUser(username, email, password string) (string, string, error) {
	username = strings.TrimSpace(username)
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

func (s *Services) prepareNewUser(username, email, password, ip string, emailVerified bool) (*model.User, error) {
	hashed, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

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
		EmailDomain:     truncate(RegistrationDomainKey(email), 128),
		EmailVerified:   emailVerified,
	}
	if group != nil {
		user.GroupID = group.ID
	}
	return user, nil
}

func (s *Services) insertUserTx(db *gorm.DB, user *model.User) error {
	if err := db.Create(user).Error; err != nil {
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

func isUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
}

func emailDomain(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

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
		// 查询失败时拒绝注册：放行等于在数据库故障时绕过域名配额。
		return fmt.Errorf("检查邮箱域名注册频率失败: %w", err)
	}
	if overLimit(n, limit, inclusive) {
		return ErrDomainRegisterLimited
	}
	return nil
}

func (s *Services) lockRegisterQuota(tx *gorm.DB, key string) error {
	return s.lockAdvisory(tx, key)
}

func overLimit(n int64, limit int, inclusive bool) bool {
	if limit <= 0 {
		return false
	}
	if inclusive {
		return n > int64(limit)
	}
	return n >= int64(limit)
}

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
		return nil
	}
	if overLimit(n, limit, inclusive) {
		return ErrRegisterLimited
	}
	return nil
}

func (s *Services) Authenticate(username, password, ip string) (*model.User, error) {
	username = strings.TrimSpace(username)
	var u model.User
	err := s.DB.Where("username = ?", username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
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
	if err := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"last_login_at": now, "last_login_ip": ip}).Error; err != nil {
		log.Printf("[auth] 记录用户 %d 的登录时间/IP 失败（登录已通过，审计字段未更新）: %v", u.ID, err)
		s.recordAuditFailure(auditScopeUserLogin, err)
	}

	return s.LoadUser(u.ID)
}

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

func (s *Services) RevealAPIKey(u *model.User) (string, error) {
	if u.APIKeyEnc == "" {
		return "", ErrNotFound
	}
	return auth.DecryptAPIKey(s.Cfg.APIKeyEncKey, u.APIKeyEnc)
}

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

func IsSafeName(s string) bool { return isSafeName(s) }
