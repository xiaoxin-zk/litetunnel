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

	group := s.defaultGroup()
	user := &model.User{
		Username:       in.Username,
		Email:          in.Email,
		Password:       hashed,
		Nickname:       in.Username,
		Status:         model.UserStatusActive,
		TrafficResetAt: time.Now().AddDate(0, 1, 0),
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

// LoadUserByUsername 按用户名载入。
func (s *Services) LoadUserByUsername(username string) (*model.User, error) {
	var u model.User
	if err := s.DB.Preload("Group").Where("username = ?", username).First(&u).Error; err != nil {
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

// UpdatePassword 修改密码。
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
	hashed, err := auth.HashPassword(newPwd)
	if err != nil {
		return err
	}
	return s.DB.Model(&model.User{}).Where("id = ?", userID).Update("password", hashed).Error
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
