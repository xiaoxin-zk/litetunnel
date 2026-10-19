package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestEnqueueMailRejectsBeforeWrite(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	sender := &fakeMailer{}
	svc.mailerOverride = sender

	const to = "enqueue@example.com"
	quota := mailQuota{cooldown: time.Minute, dailyLimit: 5}
	payload := emailCodePayload{Email: to, Scene: EmailSceneRegister, CodeHash: "h", TTLSeconds: 600}

	if _, err := svc.enqueueMail(to, "s", "body", model.MailKindEmailCodeRegister, payload, quota); err != nil {
		t.Fatalf("第一封应入队成功: %v", err)
	}
	_, err := svc.enqueueMail(to, "s", "body", model.MailKindEmailCodeRegister, payload, quota)
	if !errors.Is(err, errMailQuotaCooldown) {
		t.Fatalf("冷却窗口内应返回 errMailQuotaCooldown，实际 %v", err)
	}

	var rows int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ?", to).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("被拒绝的请求不该留下任何记录（否则失败记录会吃掉额度），实际 %d 条", rows)
	}

	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 1 {
		t.Fatalf("应发出 1 封，实际 %d 封", got)
	}
}

func TestClaimMailPreventsDoubleSend(t *testing.T) {
	svc := newTestServices(t, nil)

	row := &model.MailOutbox{
		To: "claim@example.com", Subject: "s", Kind: model.MailKindResetLink,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建待发邮件失败: %v", err)
	}

	from := []string{model.MailPending, model.MailSending}
	if _, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease); !ok {
		t.Fatal("第一次领取应成功")
	}
	if _, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease); ok {
		t.Fatal("租约内不该被再次领取（多实例会重复发信）")
	}

	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Update("next_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease); !ok {
		t.Fatal("租约到期后应可重新领取（实例崩溃恢复）")
	}

	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Updates(map[string]any{"status": model.MailFailed, "next_at": time.Now().Add(-time.Second)}).Error; err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease); ok {
		t.Fatal("已作废的邮件不该被领取")
	}
}

func TestClaimMailTokenGuardsWriteBack(t *testing.T) {
	svc := newTestServices(t, nil)

	row := &model.MailOutbox{
		To: "stale@example.com", Subject: "s", Body: "body",
		Kind: model.MailKindResetLink, Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建待发邮件失败: %v", err)
	}

	from := []string{model.MailPending, model.MailSending}
	oldToken, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease)
	if !ok {
		t.Fatal("第一次领取应成功")
	}

	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Update("next_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	newToken, ok := svc.claimMail(row.ID, from, model.MailSending, mailSendLease)
	if !ok {
		t.Fatal("租约到期后应可接手")
	}

	svc.failMail(*row, oldToken, errors.New("smtp 失败"))

	var after model.MailOutbox
	if err := svc.DB.First(&after, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailSending || after.ClaimToken != newToken {
		t.Fatalf("旧持有者的回写不该生效：status=%q token=%q（期望 sending / %q）",
			after.Status, after.ClaimToken, newToken)
	}
}

func TestActivatingMailRecoversAfterLeaseExpiry(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	svc.mailerOverride = &fakeMailer{}

	const email = "stuckactivating@example.com"
	sum := sha256.Sum256([]byte("123456"))
	payload, err := json.Marshal(emailCodePayload{
		Email: email, Scene: EmailSceneRegister,
		CodeHash: hex.EncodeToString(sum[:]), TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}

	row := &model.MailOutbox{
		To: email, Subject: "s", Kind: model.MailKindEmailCodeRegister,
		Payload: string(payload), Status: model.MailActivating,
		ClaimToken: "dead-holder", NextAt: time.Now().Add(-time.Minute),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建记录失败: %v", err)
	}

	svc.processMailOutbox(context.Background())

	var after model.MailOutbox
	if err := svc.DB.First(&after, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailSent {
		t.Fatalf("过期未完成的激活应被接手并办结，实际 %q（%s）", after.Status, after.LastErr)
	}
	var codes int64
	if err := svc.DB.Model(&model.EmailCode{}).
		Where("mail_id = ?", row.ID).Count(&codes).Error; err != nil {
		t.Fatal(err)
	}
	if codes != 1 {
		t.Fatalf("接手后应激活出验证码，实际 %d 条", codes)
	}
}

func TestCheckMailQuotaCountsFailedAttempts(t *testing.T) {
	svc := newTestServices(t, nil)

	const to = "failedcount@example.com"
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for i := 0; i < 5; i++ {
		row := &model.MailOutbox{
			To: to, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailFailed, NextAt: now, CreatedAt: dayStart.Add(time.Minute),
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("建失败邮件失败: %v", err)
		}
	}

	if err := checkMailQuota(svc.DB, to, model.MailKindResetLink,
		mailQuota{dailyLimit: 5}); !errors.Is(err, errMailQuotaDaily) {
		t.Fatalf("失败记录也应计入额度，实际 %v", err)
	}
}

func TestCheckMailQuotaDailyLimitIsExclusive(t *testing.T) {
	svc := newTestServices(t, nil)

	const to = "dailycount@example.com"
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	mk := func() {
		row := &model.MailOutbox{
			To: to, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailSent, NextAt: now, CreatedAt: dayStart.Add(time.Minute),
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("建邮件失败: %v", err)
		}
	}

	for i := 0; i < 4; i++ {
		mk()
	}
	if err := checkMailQuota(svc.DB, to, model.MailKindResetLink,
		mailQuota{dailyLimit: 5}); err != nil {
		t.Fatalf("未达上限应放行，实际 %v", err)
	}

	mk()
	if err := checkMailQuota(svc.DB, to, model.MailKindResetLink,
		mailQuota{dailyLimit: 5}); !errors.Is(err, errMailQuotaDaily) {
		t.Fatalf("达到上限应拒绝，实际 %v", err)
	}
}

func TestResetLinkRateLimitedPerEmail(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	sender := &fakeMailer{}
	svc.mailerOverride = sender

	u := &model.User{
		Username: "resetlimit", Password: "not-used", Status: model.UserStatusActive,
		Email: "resetlimit@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.requestPasswordReset(u.Username, "1.1.1.1", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码失败: %v", err)
	}
	if err := svc.requestPasswordReset(u.Username, "2.2.2.2", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码不该报错（会泄露账号状态）: %v", err)
	}

	var rows int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ?", u.Email, model.MailKindResetLink).
		Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("冷却窗口内的第二次请求不该留下记录，实际共 %d 条", rows)
	}

	nowTs := time.Now()
	dayStart := time.Date(nowTs.Year(), nowTs.Month(), nowTs.Day(), 0, 0, 0, 0, nowTs.Location())
	old := nowTs.Add(-10 * time.Minute)
	if old.Before(dayStart) {
		old = dayStart
	}
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ?", u.Email, model.MailKindResetLink).
		Update("created_at", old).Error; err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i < resetLinkDailyPerEmail; i++ {
		row := &model.MailOutbox{
			To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailSent, NextAt: old, CreatedAt: dayStart.Add(time.Minute),
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("造历史邮件失败: %v", err)
		}
	}

	if err := svc.requestPasswordReset(u.Username, "3.3.3.3", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码不该报错: %v", err)
	}
	var after int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ?", u.Email, model.MailKindResetLink).
		Count(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after != int64(resetLinkDailyPerEmail) {
		t.Fatalf("超过每日上限后不该新增记录（期望 %d 条，实际 %d 条）",
			resetLinkDailyPerEmail, after)
	}

	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 1 {
		t.Fatalf("被限流的请求不该真的发信，实际发了 %d 封", got)
	}
}
