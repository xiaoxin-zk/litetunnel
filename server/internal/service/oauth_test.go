package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func makeOAuthUser(t *testing.T, svc *Services, username, email string, verified bool) *model.User {
	t.Helper()
	u := model.User{
		Username: username, Email: email, EmailVerified: verified,
		Password: "x", Status: model.UserStatusActive, TokenVersion: 1,
	}
	if err := svc.DB.Create(&u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	return &u
}

func TestOAuthLoginBindsByVerifiedEmail(t *testing.T) {
	svc := newTestServices(t, nil)
	u := makeOAuthUser(t, svc, "oauthuser", "owner@example.com", false)

	got, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGitHub, Subject: "1001",
		Email: "owner@example.com", EmailVerified: true, Username: "owner",
	})
	if err != nil {
		t.Fatalf("已验证邮箱应允许绑定并登录: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("应登录到邮箱匹配的账号，实际 %d", got.ID)
	}

	var ident model.AuthIdentity
	if err := svc.DB.Where("provider = ? AND provider_user_id = ?", OAuthProviderGitHub, "1001").
		First(&ident).Error; err != nil {
		t.Fatalf("应写入绑定记录: %v", err)
	}
	if ident.UserID != u.ID {
		t.Fatalf("绑定关系指向了错误账号: %d", ident.UserID)
	}

	var reloaded model.User
	if err := svc.DB.First(&reloaded, u.ID).Error; err != nil {
		t.Fatalf("读用户失败: %v", err)
	}
	if !reloaded.EmailVerified {
		t.Fatal("provider 已证明邮箱归属，本站邮箱应被标记为已验证")
	}

	// 再次回调走绑定记录，不应重复插入
	again, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGitHub, Subject: "1001",
		Email: "owner@example.com", EmailVerified: true,
	})
	if err != nil || again.ID != u.ID {
		t.Fatalf("已绑定的账号应直接登录，实际 %v %v", again, err)
	}
}

func TestOAuthLoginRejectsUnverifiedEmail(t *testing.T) {
	svc := newTestServices(t, nil)
	makeOAuthUser(t, svc, "victim", "victim@example.com", true)

	_, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGitHub, Subject: "2002",
		Email: "victim@example.com", EmailVerified: false,
	})
	if !errors.Is(err, ErrOAuthEmailNotVerified) {
		t.Fatalf("未验证邮箱绝不能自动并号，实际 %v", err)
	}
}

func TestOAuthLoginRefusesToCreateAccount(t *testing.T) {
	svc := newTestServices(t, nil)

	_, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGitHub, Subject: "3003",
		Email: "nobody@example.com", EmailVerified: true,
	})
	if !errors.Is(err, ErrOAuthNoAccount) {
		t.Fatalf("没有匹配账号时应提示先注册，而不是自动建号，实际 %v", err)
	}

	var n int64
	if err := svc.DB.Model(&model.User{}).Count(&n).Error; err != nil {
		t.Fatalf("统计用户失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("第三方登录不该创建用户，实际新增 %d 个", n)
	}
}

func TestOAuthLoginRejectsDisabledBoundAccount(t *testing.T) {
	svc := newTestServices(t, nil)
	u := makeOAuthUser(t, svc, "bounddisabled", "bound@example.com", true)
	if err := svc.DB.Create(&model.AuthIdentity{
		UserID: u.ID, Provider: OAuthProviderGitHub, ProviderUserID: "5005", Email: u.Email,
	}).Error; err != nil {
		t.Fatalf("写入绑定记录失败: %v", err)
	}
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusDisabled).Error; err != nil {
		t.Fatalf("禁用用户失败: %v", err)
	}

	if _, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGitHub, Subject: "5005",
		Email: "bound@example.com", EmailVerified: true,
	}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("已绑定但被禁用的账号不能靠第三方登录绕回，实际 %v", err)
	}
}

func TestOAuthLoginRejectsDisabledAccount(t *testing.T) {
	svc := newTestServices(t, nil)
	u := makeOAuthUser(t, svc, "disableduser", "off@example.com", true)
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusDisabled).Error; err != nil {
		t.Fatalf("禁用用户失败: %v", err)
	}

	if _, err := svc.OAuthLogin(OAuthProfile{
		Provider: OAuthProviderGoogle, Subject: "4004",
		Email: "off@example.com", EmailVerified: true,
	}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("被禁用账号应拒绝登录，实际 %v", err)
	}
}

func TestOAuthAvailableRequiresCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	if svc.OAuthAvailable(OAuthProviderGitHub) {
		t.Fatal("默认应不可用")
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyOAuthGitHubEnabled: "true"}); err != nil {
		t.Fatalf("保存开关失败: %v", err)
	}
	if svc.OAuthAvailable(OAuthProviderGitHub) {
		t.Fatal("只开开关、没有凭据时不该暴露登录入口")
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyOAuthGitHubClientID:     "client-id",
		KeyOAuthGitHubClientSecret: "client-secret",
	}); err != nil {
		t.Fatalf("保存凭据失败: %v", err)
	}
	if !svc.OAuthAvailable(OAuthProviderGitHub) {
		t.Fatal("开关与凭据齐全时应可用")
	}
	if svc.OAuthAvailable(OAuthProviderGoogle) {
		t.Fatal("未配置的 provider 不该可用")
	}
}
