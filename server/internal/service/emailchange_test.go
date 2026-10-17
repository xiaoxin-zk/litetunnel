package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「换邮箱」这条路的提权风险。
//
// 背景：换邮箱原先只做格式校验就写库。拿着一个被盗会话的人可以先把邮箱
// 改成自己的，再用「找回密码」的验证码设新密码——一次临时入侵就变成长期
// 控制。现在的规则是「当前密码 + 新地址收得到验证码」两道关，缺一不可。

func strPtr(s string) *string { return &s }

// TestUpdateProfileRejectsEmailChangeWhenMailEnabled 覆盖「开邮件时直接改邮箱」。
func TestUpdateProfileRejectsEmailChangeWhenMailEnabled(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)

	u := &model.User{
		Username: "mailchange", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	_, err := svc.UpdateProfile(u.ID, ProfileUpdateInput{Email: strPtr("attacker@evil.example")})
	if err == nil {
		t.Fatal("启用邮件时，直接改邮箱必须被拒绝（否则被盗会话可以借此接管账号）")
	}
	if !strings.Contains(err.Error(), "验证") {
		t.Fatalf("错误信息应指引用户走验证流程，实际: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Email != "old@example.com" {
		t.Fatalf("被拒绝时邮箱不应改变，实际 %q", got.Email)
	}
}

// TestUpdateProfileAllowsEmailWithoutMailAndClearsVerified 覆盖「未启用邮件」的正反面。
//
// 没开邮件时邮箱只是联系方式，找不回密码，直接保存没有提权风险；
// 但「已验证」标记针对的是旧地址，换地址后必须清掉。
func TestUpdateProfileAllowsEmailWithoutMailAndClearsVerified(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "nomailchange", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if _, err := svc.UpdateProfile(u.ID, ProfileUpdateInput{Email: strPtr("New@Example.com")}); err != nil {
		t.Fatalf("未启用邮件时应允许直接保存: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Email != "new@example.com" {
		t.Fatalf("邮箱应被规范化保存，实际 %q", got.Email)
	}
	if got.EmailVerified {
		t.Fatal("换了地址必须撤销「已验证」：那个标记针对的是旧邮箱")
	}
	if got.EmailDomain != "example.com" {
		t.Fatalf("邮箱域名冗余列应同步更新，实际 %q", got.EmailDomain)
	}
}

// TestRequestEmailChangeRequiresPassword 覆盖「只凭会话就能触发换绑」。
func TestRequestEmailChangeRequiresPassword(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)

	hash, err := auth.HashPassword("Passw0rd12345")
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	u := &model.User{
		Username: "reqmail", Password: hash, Status: model.UserStatusActive,
		Email: "old@example.com",
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.RequestEmailChange(u.ID, "new@example.com", "wrong-password", "127.0.0.1"); err == nil {
		t.Fatal("密码不正确时必须拒绝，否则被盗会话可以直接把邮箱换成攻击者的")
	}

	var cnt int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("to_addr = ?", "new@example.com").Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("被拒绝时不该发出验证码，实际 %d 封", cnt)
	}
}

// TestConfirmEmailChangeApplies 覆盖换绑成功时的连带效果。
func TestConfirmEmailChangeApplies(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "confemail", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// 旧邮箱还有一条未用的重置令牌：换绑后必须作废，
	// 否则拿到旧邮箱的人仍能重置这个账号的密码。
	if err := svc.DB.Create(&model.PasswordResetToken{
		UserID: u.ID, TokenHash: "stale-token", ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("建重置令牌失败: %v", err)
	}
	seedChangeCode(t, svc, "new@example.com", "123456")

	if err := svc.ConfirmEmailChange(u.ID, "new@example.com", "123456"); err != nil {
		t.Fatalf("换绑失败: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Email != "new@example.com" {
		t.Fatalf("邮箱未更新，实际 %q", got.Email)
	}
	if !got.EmailVerified {
		t.Fatal("新地址刚刚通过验证码验证，应标记为已验证")
	}

	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("换绑后旧的密码重置令牌必须作废")
	}

	var rec model.EmailCode
	if err := svc.DB.Where("email = ? AND scene = ?", "new@example.com", EmailSceneChange).
		First(&rec).Error; err != nil {
		t.Fatal(err)
	}
	if rec.UsedAt == nil {
		t.Fatal("验证码必须被消费，否则同一个码还能再用一次")
	}
}

// TestConfirmEmailChangeRejectsTakenEmail 覆盖「新邮箱已被别人占用」。
func TestConfirmEmailChangeRejectsTakenEmail(t *testing.T) {
	svc := newTestServices(t, nil)

	other := &model.User{
		Username: "otherhold", Password: "not-used", Status: model.UserStatusActive,
		Email: "taken@example.com",
	}
	u := &model.User{
		Username: "wanttaken", Password: "not-used", Status: model.UserStatusActive,
		Email: "mine@example.com",
	}
	for _, x := range []*model.User{other, u} {
		if err := svc.DB.Create(x).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
	}
	seedChangeCode(t, svc, "taken@example.com", "654321")

	err := svc.ConfirmEmailChange(u.ID, "taken@example.com", "654321")
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("邮箱被占用时应返回 ErrEmailTaken，实际 %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Email != "mine@example.com" {
		t.Fatalf("失败时邮箱不应改变，实际 %q", got.Email)
	}

	// 失败发生在事务里：验证码不能被消费掉，用户改个邮箱还能继续用。
	var rec model.EmailCode
	if err := svc.DB.Where("email = ? AND scene = ?", "taken@example.com", EmailSceneChange).
		First(&rec).Error; err != nil {
		t.Fatal(err)
	}
	if rec.UsedAt != nil {
		t.Fatal("事务回滚后验证码不应被标记为已用")
	}
}

// seedChangeCode 直接写一条「换绑邮箱」的验证码记录，等价于邮件已经送达。
//
// 走完整链路（发信 → 投递 → 激活）拿不到明文验证码，而这里要验证的是
// 「确认换绑」这一步的语义，所以直接把码固定成已知值。
func seedChangeCode(t *testing.T, svc *Services, email, code string) {
	t.Helper()
	sum := sha256.Sum256([]byte(code))
	rec := model.EmailCode{
		Email:    email,
		Scene:    EmailSceneChange,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("写验证码失败: %v", err)
	}
}
