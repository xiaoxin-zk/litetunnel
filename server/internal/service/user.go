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
}

// Register 创建用户并绑定默认分组。
func (s *Services) Register(in RegisterInput) (*model.User, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if len(in.Username) < 3 || len(in.Username) > 32 {
		return nil, fmt.Errorf("%w: 用户名长度需为 3-32 个字符", ErrInvalidParam)
	}
	if !isSafeName(in.Username) {
		return nil, fmt.Errorf("%w: 用户名仅允许字母、数字、下划线", ErrInvalidParam)
	}
	if len(in.Password) < 8 {
		return nil, fmt.Errorf("%w: 密码长度不得少于 8 位", ErrInvalidParam)
	}
	if in.Email != "" && !IsValidEmail(in.Email) {
		return nil, fmt.Errorf("%w: 邮箱格式不正确", ErrInvalidParam)
	}

	var exists int64
	if err := s.DB.Model(&model.User{}).Where("username = ?", in.Username).Count(&exists).Error; err != nil {
		return nil, err
	}
	if exists > 0 {
		return nil, ErrUsernameTaken
	}

	hashed, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	// 注册即生成 API Key：桌面客户端只用这一把凭据登录，
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
		Username:        in.Username,
		Email:           in.Email,
		Password:        hashed,
		Nickname:        in.Username,
		Status:          model.UserStatusActive,
		TrafficResetAt:  time.Now().AddDate(0, 1, 0),
		APIKeyHash:      apiHash,
		APIKeyPrefix:    apiPrefix,
		APIKeyEnc:       apiEnc,
		APIKeyCreatedAt: &now,
	}
	if group != nil {
		user.GroupID = group.ID
	}
	if err := s.DB.Create(user).Error; err != nil {
		// 并发注册时可能撞唯一索引，转为友好错误。
		return nil, ErrUsernameTaken
	}
	return s.LoadUser(user.ID)
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

	err := s.DB.Transaction(func(tx *gorm.DB) error {
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

	s.Runtime.SetQuotaExceeded(userID, false)
	s.Runtime.InvalidateIdentity(IdentityKindUser, userID)
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
