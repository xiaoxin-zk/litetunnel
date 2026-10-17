package service

import (
	"context"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守两件与「发信额度」有关的事：
//
//  1. 额度复核必须发生在**发送之前**——否则信已经在路上，作废只能拦住
//     凭据生效，拦不住收件人收到一个无效验证码。
//  2. 找回密码链接也要按收件地址限流——按 IP 的令牌桶挡不住分布式来源
//     对同一个邮箱持续排队。

// TestQueueMailStartsAsDraftAndOnlyReleaseMakesItSendable 覆盖「先发后查」。
func TestQueueMailStartsAsDraftAndOnlyReleaseMakesItSendable(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	sender := &fakeMailer{}
	svc.mailerOverride = sender

	const to = "draft@example.com"
	row, err := svc.queueMail(to, "s", "body", model.MailKindEmailCodeRegister,
		emailCodePayload{Email: to, Scene: EmailSceneRegister, CodeHash: "h", TTLSeconds: 600})
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if row.Status != model.MailDraft {
		t.Fatalf("入队后应是草稿（worker 不会取），实际 %q", row.Status)
	}

	// 草稿状态下发信协程不该发出任何东西。
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 0 {
		t.Fatalf("草稿不该被发送，实际发了 %d 封", got)
	}

	// 作废之后即便再尝试释放也不会发出去。
	svc.voidMail(row.ID, "额度超限")
	if svc.releaseMail(row.ID) {
		t.Fatal("已作废的邮件不该被释放")
	}
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 0 {
		t.Fatalf("作废后不该发送，实际发了 %d 封", got)
	}

	// 正常路径：释放之后才真正发出。
	row2, err := svc.queueMail(to, "s", "body", model.MailKindEmailCodeRegister,
		emailCodePayload{Email: to, Scene: EmailSceneRegister, CodeHash: "h2", TTLSeconds: 600})
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if !svc.releaseMail(row2.ID) {
		t.Fatal("草稿应能被释放为待发送")
	}
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got != 1 {
		t.Fatalf("释放后应发出一封，实际 %d 封", got)
	}
}

// TestResetLinkRateLimitedPerEmail 覆盖「按邮箱的找回链接限流」。
//
// 同一邮箱连续请求：冷却窗口内的第二封必须被作废（不发信）；
// 当日数量超过上限时同样作废。响应本身始终一致，不泄露账号状态。
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
	// 第二次（立刻，换个 IP 也绕不过）：冷却窗口内，应静默作废。
	if err := svc.RequestPasswordReset(u.Username, "2.2.2.2", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码不该报错（会泄露账号状态）: %v", err)
	}

	var live int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ? AND status <> ?",
			u.Email, model.MailKindResetLink, model.MailFailed).
		Count(&live).Error; err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("同一邮箱短时间内只该有一封有效找回邮件，实际 %d 封", live)
	}

	// 当日上限：把已有记录推到冷却窗口之外，再补到上限。
	old := time.Now().Add(-10 * time.Minute)
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ?", u.Email, model.MailKindResetLink).
		Update("created_at", old).Error; err != nil {
		t.Fatal(err)
	}
	// 用**本地**零点：服务端的当日统计也是按本地时区算的，
	// 拿 Truncate(24h) 会得到 UTC 边界，在非零时区会落到昨天。
	nowTs := time.Now()
	dayStart := time.Date(nowTs.Year(), nowTs.Month(), nowTs.Day(), 0, 0, 0, 0, nowTs.Location())
	for i := int64(0); i < resetLinkDailyPerEmail; i++ {
		row := &model.MailOutbox{
			To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailSent, NextAt: old, CreatedAt: dayStart.Add(time.Minute),
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("造历史邮件失败: %v", err)
		}
	}

	// 记录「可发送」的封数作为基线：第一封正常排队的仍留在 pending 里。
	var before int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ? AND status IN ?",
			u.Email, model.MailKindResetLink, []string{model.MailDraft, model.MailPending}).
		Count(&before).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.RequestPasswordReset(u.Username, "3.3.3.3", "https://panel.example.com"); err != nil {
		t.Fatalf("找回密码不该报错: %v", err)
	}

	var after int64
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ? AND kind = ? AND status IN ?",
			u.Email, model.MailKindResetLink, []string{model.MailDraft, model.MailPending}).
		Count(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("超过每日上限后不该新增可发送邮件（前 %d，后 %d）", before, after)
	}

	// 全程没有发信：作废发生在 release 之前。
	svc.processMailOutbox(context.Background())
	if got := sender.sentCount(); got > resetLinkDailyPerEmail {
		t.Fatalf("被限流的请求不该真的发信，实际发了 %d 封", got)
	}
}

// TestRecheckResetLinkQuotaCountsSelf 覆盖额度统计「含自己」的口径。
func TestRecheckResetLinkQuotaCountsSelf(t *testing.T) {
	svc := newTestServices(t, nil)

	const to = "selfcount@example.com"
	now := time.Now()
	mk := func(createdAt time.Time) *model.MailOutbox {
		row := &model.MailOutbox{
			To: to, Subject: "s", Kind: model.MailKindResetLink,
			Status: model.MailDraft, NextAt: now, CreatedAt: createdAt,
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("建邮件失败: %v", err)
		}
		return row
	}

	// 正好等于上限（含自己）时应当放行。
	old := now.Add(-10 * time.Minute)
	for i := int64(0); i < resetLinkDailyPerEmail-1; i++ {
		mk(old)
	}
	last := mk(old)
	if err := svc.recheckResetLinkQuota(last); err != nil {
		t.Fatalf("恰好达到上限应放行，实际 %v", err)
	}

	// 再多一封就超了。
	extra := mk(old)
	if err := svc.recheckResetLinkQuota(extra); err == nil {
		t.Fatal("超过上限应返回错误（由调用方作废这封）")
	}
}
