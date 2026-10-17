package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守两件与「发信额度」有关的事：
//
//  1. 额度复核必须发生在**写入之前**：先写再查的话，一批并发请求会各自
//     留下记录、各自超限，而这些失败记录还会继续占额度，把当日额度耗光。
//  2. 找回密码链接也要按收件地址限流——按 IP 的令牌桶挡不住分布式来源
//     对同一个邮箱持续排队。

// TestEnqueueMailRejectsBeforeWrite 覆盖「超限时不写任何记录」。
//
// 这是并发突发的关键：如果先写再查，10 个并发请求会留下 10 条失败记录，
// 而额度统计会把它们算进去，用户当天再也发不出去。
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
	// 冷却窗口内再来一封：拒绝，且**不留记录**。
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

	// 正常入队的那封会被发出去。
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 1 {
		t.Fatalf("应发出 1 封，实际 %d 封", got)
	}
}

// TestClaimMailPreventsDoubleSend 覆盖「多实例重复发信」。
//
// 每个实例都有自己的发件协程。直接读 pending 就发的话，同一行会被两个实例
// 各发一次（收件人收到两封、凭据被激活两次）。领取是条件更新：
// 只有 RowsAffected=1 的实例继续发。实例在发送途中崩溃时，租约到期后
// 另一个实例可以接手。
func TestClaimMailPreventsDoubleSend(t *testing.T) {
	svc := newTestServices(t, nil)

	row := &model.MailOutbox{
		To: "claim@example.com", Subject: "s", Kind: model.MailKindResetLink,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建待发邮件失败: %v", err)
	}

	now := time.Now()
	if !svc.claimMail(row.ID, now) {
		t.Fatal("第一次领取应成功")
	}
	if svc.claimMail(row.ID, now) {
		t.Fatal("租约内不该被再次领取（多实例会重复发信）")
	}

	// 租约到期：崩溃恢复，允许重新领取。
	if !svc.claimMail(row.ID, now.Add(mailSendLease+time.Second)) {
		t.Fatal("租约到期后应可重新领取（实例崩溃恢复）")
	}

	// 已作废的邮件不该被领取。
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Update("status", model.MailFailed).Error; err != nil {
		t.Fatal(err)
	}
	if svc.claimMail(row.ID, now.Add(2*mailSendLease)) {
		t.Fatal("已作废的邮件不该被领取")
	}
}

// TestCheckMailQuotaCountsFailedAttempts 覆盖「额度约束请求而不是投递结果」。
//
// 失败的信同样是一次真实的发送请求：SMTP 故障期间若不计入额度，
// 分散来源可以无限重新排队，把队列与重试都打满。
// 「失败记录吃掉额度」的问题由「先复核、后写入」解决——配额不足的请求
// 根本不会留下记录。
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

// TestCheckMailQuotaDailyLimitIsExclusive 钉住「不含自己」的口径。
//
// 复核发生在写入之前，所以「已有 N 条」时，N == limit 就该拒绝；
// 口径写成 inclusive 会每天多放一封。
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

	mk() // 达到 5 条
	if err := checkMailQuota(svc.DB, to, model.MailKindResetLink,
		mailQuota{dailyLimit: 5}); !errors.Is(err, errMailQuotaDaily) {
		t.Fatalf("达到上限应拒绝，实际 %v", err)
	}
}

// TestResetLinkRateLimitedPerEmail 覆盖「按邮箱的找回链接限流」。
//
// 同一邮箱连续请求：冷却窗口内的第二封直接被拒（不写记录）；
// 当日数量达到上限时同样拒绝。响应本身始终一致，不泄露账号状态。
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

	// 第一次：正常排队。
	if err := svc.RequestPasswordReset(u.Username, "1.1.1.1", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码失败: %v", err)
	}
	// 第二次（立刻，换个 IP 也绕不过）：冷却窗口内，静默拒绝且不写记录。
	if err := svc.RequestPasswordReset(u.Username, "2.2.2.2", "https://panel.example.com"); err != nil {
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

	// 当日上限：把这封推到冷却窗口之外，再补到上限。
	old := time.Now().Add(-10 * time.Minute)
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ?", u.Email, model.MailKindResetLink).
		Update("created_at", old).Error; err != nil {
		t.Fatal(err)
	}
	nowTs := time.Now()
	dayStart := time.Date(nowTs.Year(), nowTs.Month(), nowTs.Day(), 0, 0, 0, 0, nowTs.Location())
	for i := int64(1); i < resetLinkDailyPerEmail; i++ {
		row := &model.MailOutbox{
			To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailSent, NextAt: old, CreatedAt: dayStart.Add(time.Minute),
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("造历史邮件失败: %v", err)
		}
	}

	if err := svc.RequestPasswordReset(u.Username, "3.3.3.3", "https://panel.example.com"); err != nil {
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

	// 只有第一封会被真正发出去。
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 1 {
		t.Fatalf("被限流的请求不该真的发信，实际发了 %d 封", got)
	}
}
