package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func strPtr(s string) *string { return &s }

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

func TestUpdateProfileAllowsEmailWithoutMailAndClearsVerified(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "nomailchange", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true, EmailDomain: "example.com",
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
		t.Fatalf("注册来源域名不应随换邮箱变化，实际 %q", got.EmailDomain)
	}
}

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

func TestConfirmEmailChangeApplies(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "confemail", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
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

	var rec model.EmailCode
	if err := svc.DB.Where("email = ? AND scene = ?", "taken@example.com", EmailSceneChange).
		First(&rec).Error; err != nil {
		t.Fatal(err)
	}
	if rec.UsedAt != nil {
		t.Fatal("事务回滚后验证码不应被标记为已用")
	}
}

func TestUpdateProfileWithoutMailPurgesOldCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	const oldEmail = "legacy@example.com"
	u := &model.User{
		Username: "legacymail", Password: "not-used", Status: model.UserStatusActive,
		Email: oldEmail, EmailVerified: true, EmailDomain: "example.com",
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Create(&model.PasswordResetToken{
		UserID: u.ID, TokenHash: "legacy-token", ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("建重置令牌失败: %v", err)
	}
	mail := &model.MailOutbox{
		To: oldEmail, Subject: "s", Body: "code=123456", Kind: model.MailKindEmailCodeReset,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(mail).Error; err != nil {
		t.Fatalf("建待发邮件失败: %v", err)
	}

	if _, err := svc.UpdateProfile(u.ID, ProfileUpdateInput{Email: strPtr("new@example.com")}); err != nil {
		t.Fatalf("未启用邮件时应允许直接改: %v", err)
	}

	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("改邮箱后旧的重置令牌必须作废：它按用户 ID 生效，不核对邮箱")
	}

	var after model.MailOutbox
	if err := svc.DB.First(&after, mail.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailFailed || after.Body != "" || after.Payload != "" {
		t.Fatalf("旧地址的待发邮件必须作废并清空内容，实际 status=%s body=%q", after.Status, after.Body)
	}
}

func TestForgotPasswordRequiresVerifiedEmail(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)

	u := &model.User{
		Username: "unverified", Password: "not-used", Status: model.UserStatusActive,
		Email: "unverified@example.com",
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.requestPasswordReset(u.Username, "127.0.0.1", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码接口不该因此报错（会泄露账号状态）: %v", err)
	}

	var cnt int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ?", u.Email).Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("未验证的邮箱不该收到重置邮件，实际 %d 封", cnt)
	}
}

func TestEmailUniquenessIsCaseInsensitive(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "mixedcase", Password: "not-used", Status: model.UserStatusActive,
		Email: "Mixed@Example.com",
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.checkUserUnique("another", "mixed@example.com"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("大小写不同仍是同一个邮箱，应返回 ErrEmailTaken，实际 %v", err)
	}

	other := &model.User{
		Username: "wantmixed", Password: "not-used", Status: model.UserStatusActive,
		Email: "mine@example.com",
	}
	if err := svc.DB.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	seedChangeCode(t, svc, "mixed@example.com", "112233")
	if err := svc.ConfirmEmailChange(other.ID, "MIXED@example.com", "112233"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("换绑时也必须大小写不敏感地判重，实际 %v", err)
	}
}

func TestDeliverMailSkipsActivationWhenVoided(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)

	const oldEmail = "voided@example.com"
	u := &model.User{
		Username: "voidedmail", Password: "not-used", Status: model.UserStatusActive,
		Email: oldEmail, EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	raw, err := json.Marshal(resetLinkPayload{UserID: u.ID, TokenHash: "voided-token", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	row := model.MailOutbox{
		To: oldEmail, Subject: "s", Body: "link", Kind: model.MailKindResetLink,
		Payload: string(raw), Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(&row).Error; err != nil {
		t.Fatalf("建待发邮件失败: %v", err)
	}

	token, ok := svc.claimMail(row.ID, []string{model.MailPending, model.MailSending},
		model.MailSending, mailSendLease)
	if !ok {
		t.Fatal("领取待发邮件失败")
	}
	svc.voidMail(row.ID, "邮箱已更换，邮件作废")
	if err := svc.DB.First(&row, row.ID).Error; err != nil {
		t.Fatal(err)
	}

	svc.mailerOverride = &fakeMailer{}
	svc.deliverMail(context.Background(), row, token)

	var after model.MailOutbox
	if err := svc.DB.First(&after, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailFailed {
		t.Fatalf("已作废的邮件不能被 worker 改写状态，实际 %q", after.Status)
	}
	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("token_hash = ?", "voided-token").Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("已作废的邮件不得再激活出重置令牌")
	}
}

func TestActivateResetTokenRejectsChangedAddress(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "changedaddr", Password: "not-used", Status: model.UserStatusActive,
		Email: "current@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	row := mkOutboxRow(t, svc, model.MailKindResetLink, "old@example.com",
		resetLinkPayload{UserID: u.ID, TokenHash: "stale-addr", TTLSeconds: 600})

	if err := svc.applyMailAction(row, claimForTest(t, svc, row)); !errors.Is(err, errMailActionObsolete) {
		t.Fatalf("收件地址已不是账号当前邮箱，激活应作废，实际 %v", err)
	}
	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("token_hash = ?", "stale-addr").Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("旧地址的邮件不得激活出重置令牌")
	}
}

func TestConfirmEmailChangeBlocksStaleResetActivation(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "stalelink", Password: "not-used", Status: model.UserStatusActive,
		Email: "oldaddr@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	stale := mkOutboxRow(t, svc, model.MailKindResetLink, "oldaddr@example.com",
		resetLinkPayload{UserID: u.ID, TokenHash: "stale-link", TTLSeconds: 600})

	seedChangeCode(t, svc, "newaddr@example.com", "445566")
	if err := svc.ConfirmEmailChange(u.ID, "newaddr@example.com", "445566"); err != nil {
		t.Fatalf("换绑失败: %v", err)
	}

	var after model.MailOutbox
	if err := svc.DB.First(&after, stale.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailFailed {
		t.Fatalf("换绑后旧地址的待激活邮件应被作废，实际 %q", after.Status)
	}
	if _, ok := svc.claimMail(stale.ID, []string{model.MailDelivered},
		model.MailActivating, mailActivateLease); ok {
		t.Fatal("已作废的邮件不该被领取激活")
	}

	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("token_hash = ?", "stale-link").Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("换绑后不得再激活出旧地址的重置令牌")
	}
}

func TestUpdateProfileRollsBackEmailWhenOtherFieldFails(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.DB.Create(&model.User{
		Username: "takenname", Password: "not-used", Status: model.UserStatusActive,
		Email: "taken@example.com",
	}).Error; err != nil {
		t.Fatalf("建占用用户失败: %v", err)
	}
	u := &model.User{
		Username: "oldname", Password: "not-used", Status: model.UserStatusActive,
		Email: "old@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	_, err := svc.UpdateProfile(u.ID, ProfileUpdateInput{
		Username: strPtr("takenname"),
		Email:    strPtr("new@example.com"),
	})
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("重名应返回 ErrUsernameTaken，实际 %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Email != "old@example.com" {
		t.Fatalf("用户名冲突时邮箱必须一起回滚，实际 %q", got.Email)
	}
	if !got.EmailVerified {
		t.Fatal("回滚后「已验证」标记应保持原样")
	}
}

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
