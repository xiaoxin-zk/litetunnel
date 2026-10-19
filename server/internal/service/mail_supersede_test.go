package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func claimForTest(t *testing.T, svc *Services, row model.MailOutbox) string {
	t.Helper()
	token, ok := svc.claimMail(row.ID, []string{model.MailDelivered},
		model.MailActivating, mailActivateLease)
	if !ok {
		t.Fatalf("领取邮件失败（id=%d，状态 %s）", row.ID, row.Status)
	}
	return token
}

func mkOutboxRow(t *testing.T, svc *Services, kind, to string, payload any) model.MailOutbox {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	row := model.MailOutbox{
		To:      to,
		Subject: "s",
		Kind:    kind,
		Payload: string(raw),
		Status:  model.MailDelivered,
		NextAt:  time.Now().Add(-time.Second),
	}
	if err := svc.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func countResetTokens(t *testing.T, svc *Services, where string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where(where, args...).Count(&n).Error; err != nil {
		t.Fatalf("统计令牌失败: %v", err)
	}
	return n
}

func TestResetTokenActionSupersededByNewer(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "supersede", Password: "not-used", Status: model.UserStatusActive,
		Email: "supersede@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	rowOld := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-old", TTLSeconds: 600})
	rowNew := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-new", TTLSeconds: 600})
	if rowNew.ID <= rowOld.ID {
		t.Fatalf("前置条件：新邮件 ID 应更大（%d ≤ %d）", rowNew.ID, rowOld.ID)
	}

	tokNew := model.PasswordResetToken{UserID: u.ID, TokenHash: "hash-new",
		ExpireAt: time.Now().Add(time.Hour), MailID: rowNew.ID}
	if err := svc.DB.Create(&tokNew).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.applyMailAction(rowOld, claimForTest(t, svc, rowOld)); err == nil {
		t.Fatal("旧邮件的激活应报告被取代，而不是静默成功")
	}

	if got := countResetTokens(t, svc, "token_hash = ?", "hash-old"); got != 0 {
		t.Fatalf("旧令牌不应被创建，实际 %d 条", got)
	}
	var still model.PasswordResetToken
	if err := svc.DB.Where("token_hash = ?", "hash-new").First(&still).Error; err != nil {
		t.Fatalf("新令牌应仍在: %v", err)
	}
	if still.UsedAt != nil {
		t.Fatal("新令牌被旧邮件的重试作废了")
	}
}

func TestResetTokenSupersededEvenAfterNewOneUsed(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "supersedeused", Password: "not-used",
		Status: model.UserStatusActive, Email: "used@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	rowOld := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-old", TTLSeconds: 600})
	rowNew := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-new", TTLSeconds: 600})

	used := time.Now()
	tokNew := model.PasswordResetToken{UserID: u.ID, TokenHash: "hash-new",
		ExpireAt: time.Now().Add(time.Hour), UsedAt: &used, MailID: rowNew.ID}
	if err := svc.DB.Create(&tokNew).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.applyMailAction(rowOld, claimForTest(t, svc, rowOld)); err == nil {
		t.Fatal("较新凭据已被使用，旧邮件的激活仍应被拒绝")
	}
	if got := countResetTokens(t, svc, "token_hash = ?", "hash-old"); got != 0 {
		t.Fatalf("旧链接不得被重新激活，实际 %d 条", got)
	}
}

func TestMailActionReplayIdempotent(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "replay", Password: "not-used", Status: model.UserStatusActive,
		Email: "replay@example.com", EmailVerified: true}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	row := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-once", TTLSeconds: 600})

	if err := svc.applyMailAction(row, claimForTest(t, svc, row)); err != nil {
		t.Fatalf("首次激活应成功: %v", err)
	}
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Updates(map[string]any{
			"status":      model.MailDelivered,
			"claim_token": "",
			"next_at":     time.Now().Add(-time.Second),
		}).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.applyMailAction(row, claimForTest(t, svc, row)); err != nil {
		t.Fatalf("重放应幂等成功: %v", err)
	}
	if got := countResetTokens(t, svc, "token_hash = ?", "hash-once"); got != 1 {
		t.Fatalf("重放不得重复建令牌，实际 %d 条", got)
	}
	var saved model.PasswordResetToken
	if err := svc.DB.Where("token_hash = ?", "hash-once").First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.MailID != row.ID {
		t.Fatalf("令牌应记录激活它的邮件 ID，实际 %d（期望 %d）", saved.MailID, row.ID)
	}
}

func TestEmailCodeActionSupersededByNewer(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "codesupersede@example.com"

	rowOld := mkOutboxRow(t, svc, model.MailKindEmailCodeReset, email,
		emailCodePayload{Email: email, Scene: "reset", CodeHash: "code-hash-old", TTLSeconds: 600})
	rowNew := mkOutboxRow(t, svc, model.MailKindEmailCodeReset, email,
		emailCodePayload{Email: email, Scene: "reset", CodeHash: "code-hash-new", TTLSeconds: 600})

	used := time.Now()
	codeNew := model.EmailCode{Email: email, Scene: "reset", CodeHash: "code-hash-new",
		ExpireAt: time.Now().Add(time.Hour), UsedAt: &used, MailID: rowNew.ID}
	if err := svc.DB.Create(&codeNew).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.applyMailAction(rowOld, claimForTest(t, svc, rowOld)); err == nil {
		t.Fatal("旧验证码邮件的激活应报告被取代（新码已使用同样算更新）")
	}
	var n int64
	if err := svc.DB.Model(&model.EmailCode{}).
		Where("email = ? AND code_hash = ?", email, "code-hash-old").
		Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("旧验证码不应被创建，实际 %d 条", n)
	}
}
