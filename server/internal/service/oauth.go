package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	OAuthProviderGitHub = "github"
	OAuthProviderGoogle = "google"
)

var (
	ErrOAuthDisabled         = errors.New("该登录方式未启用")
	ErrOAuthProviderFailed   = errors.New("第三方账号信息获取失败，请稍后重试")
	ErrOAuthEmailNotVerified = errors.New("该第三方账号没有已验证的邮箱，无法确定身份，请先用邮箱注册后使用密码登录")
	ErrOAuthNoAccount        = errors.New("本站没有与该第三方账号邮箱匹配的账号，请先注册后再登录")
	ErrOAuthIdentityConflict = errors.New("该第三方账号已绑定其他本站账号")
)

type OAuthProfile struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
}

var oauthHTTPClient = &http.Client{Timeout: 12 * time.Second}

func (s *Services) oauthCredentials(provider string) (clientID, clientSecret string, ok bool) {
	switch provider {
	case OAuthProviderGitHub:
		clientID = s.Settings.Get(KeyOAuthGitHubClientID)
		clientSecret = s.Settings.Get(KeyOAuthGitHubClientSecret)
		ok = s.Settings.Bool(KeyOAuthGitHubEnabled)
	case OAuthProviderGoogle:
		clientID = s.Settings.Get(KeyOAuthGoogleClientID)
		clientSecret = s.Settings.Get(KeyOAuthGoogleClientSecret)
		ok = s.Settings.Bool(KeyOAuthGoogleEnabled)
	default:
		return "", "", false
	}
	return clientID, clientSecret, ok && clientID != "" && clientSecret != ""
}

// OAuthAvailable 同时要求开关打开与凭据齐全，避免只填了一半就暴露登录按钮。
func (s *Services) OAuthAvailable(provider string) bool {
	_, _, ok := s.oauthCredentials(provider)
	return ok
}

// PanelBaseURL 是对外可访问的面板地址，OAuth 回调与前端跳转都以它为准。
func (s *Services) PanelBaseURL() string {
	if d := normalizeDomainValue(s.Settings.Get(KeyDomainPanel)); d != "" {
		return "https://" + d
	}
	return strings.TrimRight(s.UserPublicURL(), "/")
}

func (s *Services) OAuthRedirectURL(provider string) string {
	return s.PanelBaseURL() + "/api/auth/oauth/" + provider + "/callback"
}

func (s *Services) OAuthAuthorizeURL(provider, state string) (string, error) {
	clientID, _, ok := s.oauthCredentials(provider)
	if !ok {
		return "", ErrOAuthDisabled
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("state", state)
	q.Set("redirect_uri", s.OAuthRedirectURL(provider))

	switch provider {
	case OAuthProviderGitHub:
		q.Set("scope", "read:user user:email")
		return "https://github.com/login/oauth/authorize?" + q.Encode(), nil
	case OAuthProviderGoogle:
		q.Set("response_type", "code")
		q.Set("scope", "openid email profile")
		q.Set("access_type", "online")
		return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode(), nil
	}
	return "", ErrOAuthDisabled
}

type oauthTokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
}

func (s *Services) exchangeOAuthCode(ctx context.Context, provider, code string) (string, error) {
	_, secret, ok := s.oauthCredentials(provider)
	if !ok {
		return "", ErrOAuthDisabled
	}
	form := url.Values{}
	form.Set("client_id", s.oauthClientID(provider))
	form.Set("client_secret", secret)
	form.Set("code", code)
	form.Set("redirect_uri", s.OAuthRedirectURL(provider))
	form.Set("grant_type", "authorization_code")

	endpoint := "https://oauth2.googleapis.com/token"
	if provider == OAuthProviderGitHub {
		endpoint = "https://github.com/login/oauth/access_token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProviderFailed, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthProviderFailed, err)
	}
	var tr oauthTokenResp
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" || tr.Error != "" {
		return "", ErrOAuthProviderFailed
	}
	return tr.AccessToken, nil
}

func (s *Services) oauthClientID(provider string) string {
	id, _, _ := s.oauthCredentials(provider)
	return id
}

func (s *Services) oauthGet(ctx context.Context, endpoint, token string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "LiteTunnel")

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOAuthProviderFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrOAuthProviderFailed
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dest)
}

// OAuthFetchProfile 用授权码换取第三方账号信息。邮箱必须来自 provider 的已验证声明。
func (s *Services) OAuthFetchProfile(ctx context.Context, provider, code string) (OAuthProfile, error) {
	token, err := s.exchangeOAuthCode(ctx, provider, code)
	if err != nil {
		return OAuthProfile{}, err
	}

	switch provider {
	case OAuthProviderGitHub:
		var u struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Email string `json:"email"`
		}
		if err := s.oauthGet(ctx, "https://api.github.com/user", token, &u); err != nil {
			return OAuthProfile{}, err
		}
		p := OAuthProfile{
			Provider: provider,
			Subject:  fmt.Sprintf("%d", u.ID),
			Username: u.Login,
			Email:    strings.ToLower(strings.TrimSpace(u.Email)),
		}
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := s.oauthGet(ctx, "https://api.github.com/user/emails", token, &emails); err != nil {
			return OAuthProfile{}, err
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				p.Email, p.EmailVerified = strings.ToLower(e.Email), true
				break
			}
		}
		if !p.EmailVerified {
			for _, e := range emails {
				if e.Verified {
					p.Email, p.EmailVerified = strings.ToLower(e.Email), true
					break
				}
			}
		}
		if p.EmailVerified && p.Email == "" {
			p.EmailVerified = false
		}
		return p, nil

	case OAuthProviderGoogle:
		var u struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := s.oauthGet(ctx, "https://www.googleapis.com/oauth2/v3/userinfo", token, &u); err != nil {
			return OAuthProfile{}, err
		}
		return OAuthProfile{
			Provider:      provider,
			Subject:       u.Sub,
			Email:         strings.ToLower(strings.TrimSpace(u.Email)),
			EmailVerified: u.EmailVerified,
			Username:      u.Name,
		}, nil
	}
	return OAuthProfile{}, ErrOAuthDisabled
}

// OAuthLogin 只做两件事：已绑定过的直接登录；未绑定但 provider 给出了已验证邮箱且本站存在同邮箱账号，
// 则补一条绑定记录后登录。没有匹配账号时返回错误，不自动建号——否则等于绕过注册开关、
// 注册配额与邮箱域名白名单。
func (s *Services) OAuthLogin(p OAuthProfile) (*model.User, error) {
	if p.Provider == "" || p.Subject == "" {
		return nil, ErrOAuthProviderFailed
	}

	var ident model.AuthIdentity
	err := s.DB.Where("provider = ? AND provider_user_id = ?", p.Provider, p.Subject).First(&ident).Error
	if err == nil {
		return s.LoadUser(ident.UserID)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if !p.EmailVerified || p.Email == "" {
		return nil, ErrOAuthEmailNotVerified
	}

	var u model.User
	err = s.DB.Where("lower(email) = ?", p.Email).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrOAuthNoAccount
	}
	if err != nil {
		return nil, err
	}
	if u.Status != model.UserStatusActive {
		return nil, ErrAccountDisabled
	}

	row := model.AuthIdentity{
		UserID:         u.ID,
		Provider:       p.Provider,
		ProviderUserID: p.Subject,
		Email:          p.Email,
	}
	if err := s.DB.Create(&row).Error; err != nil {
		// 并发下可能已被同一账号的另一次回调写入，回查一次即可
		var again model.AuthIdentity
		if e := s.DB.Where("provider = ? AND provider_user_id = ?", p.Provider, p.Subject).
			First(&again).Error; e == nil {
			return s.LoadUser(again.UserID)
		}
		return nil, ErrOAuthIdentityConflict
	}

	// provider 已证明该邮箱归属，顺手把本站邮箱标记为已验证。
	if !u.EmailVerified {
		if err := s.DB.Model(&model.User{}).Where("id = ?", u.ID).
			Update("email_verified", true).Error; err != nil {
			return nil, err
		}
		u.EmailVerified = true
	}
	return &u, nil
}
