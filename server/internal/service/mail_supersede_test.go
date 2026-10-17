package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这一组守的是「邮件凭据只有最新代次能生效」：
// 较早邮件的激活动作在退避重试时，不得作废较新邮件刚生效的凭据，
// 也不得在重放时重复创建凭据。
//
// 先后关系由凭据上的 MailID（发件箱记录 ID）判定，而不是 created_at：
// SQLite 的时间精度是秒级，同一秒内的两封信比不出先后；而且较新的凭据
// 被用户用掉之后，这个「谁更新」的关系仍要保留——否则旧邮件的延迟重试
// 会看不到它，把旧链接重新激活。

// mkOutboxRow 插入一封「已送达、待激活」的发件箱记录并返回（ID 由库分配）。
// 不需要回拨 created_at：取代判定只看 ID。
// claimForTest 领取一封「已送达、待激活」的邮件，返回领取令牌。
//
// 激活动作现在要求调用方先领取（多实例下防止同一封信被激活两次），
// 测试也走同一条路径，而不是绕过领取直接调用。
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

// TestResetTokenActionSupersededByNewer 覆盖「较晚的凭据胜出」。
//
// 场景：较早的邮件送达后激活失败进入退避；期间用户又请求了新的重置链接，
// 新邮件先一步送达并激活成功。旧动作重试若照常执行，「作废全部未使用令牌
// + 建旧令牌」会让用户手里最新的链接失效、反而复活最旧的。
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

	// 新邮件已激活：它的未使用令牌带着自己的 MailID。
	tokNew := model.PasswordResetToken{UserID: u.ID, TokenHash: "hash-new",
		ExpireAt: time.Now().Add(time.Hour), MailID: rowNew.ID}
	if err := svc.DB.Create(&tokNew).Error; err != nil {
		t.Fatal(err)
	}

	// 旧动作重试：必须识别「已被取代」，跳过激活。
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

// TestResetTokenSupersededEvenAfterNewOneUsed 覆盖「较新凭据已被使用」。
//
// 用户可能已经用新邮件里的链接改完密码，令牌随即被消费（used_at 置位）。
// 此时旧邮件的延迟重试仍然必须放弃：否则它会把旧链接重新激活成一个
// 可用的凭据——而那是用户早就不要的那一份。
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

// TestMailActionReplayIdempotent 覆盖「动作重放幂等」。
//
// 激活成功但写终态失败时，下一轮会按原参数重放同一动作：
// 凭据仍在（同一摘要）就必须直接按成功处理，不能重复建记录——
// 否则同一条重置链接在库里会有多份，且唯一索引会让重放直接报错。
func TestMailActionReplayIdempotent(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "replay", Password: "not-used", Status: model.UserStatusActive,
		// 已验证：重置链接只对账号当前且已验证的邮箱激活（换绑后旧地址的邮件作废）。
		Email: "replay@example.com", EmailVerified: true}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	row := mkOutboxRow(t, svc, model.MailKindResetLink, u.Email,
		resetLinkPayload{UserID: u.ID, TokenHash: "hash-once", TTLSeconds: 600})

	if err := svc.applyMailAction(row, claimForTest(t, svc, row)); err != nil {
		t.Fatalf("首次激活应成功: %v", err)
	}
	// 重放：模拟「凭据已生效、但终态没写回」的那次重试——
	// 把状态放回待激活，再领一次并执行同一个动作。
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
	// 激活记录带着发件箱 ID，供后续「谁更新」的判定使用。
	var saved model.PasswordResetToken
	if err := svc.DB.Where("token_hash = ?", "hash-once").First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.MailID != row.ID {
		t.Fatalf("令牌应记录激活它的邮件 ID，实际 %d（期望 %d）", saved.MailID, row.ID)
	}
}

// TestEmailCodeActionSupersededByNewer 覆盖验证码的同类取代判定。
//
// 与重置链接同一竞态：较早邮件的激活重试不得作废较新邮件刚生效的验证码；
// 新码被用掉之后，旧动作的重试同样必须放弃。
func TestEmailCodeActionSupersededByNewer(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "codesupersede@example.com"

	rowOld := mkOutboxRow(t, svc, model.MailKindEmailCodeReset, email,
		emailCodePayload{Email: email, Scene: "reset", CodeHash: "code-hash-old", TTLSeconds: 600})
	rowNew := mkOutboxRow(t, svc, model.MailKindEmailCodeReset, email,
		emailCodePayload{Email: email, Scene: "reset", CodeHash: "code-hash-new", TTLSeconds: 600})

	// 新验证码已激活，并且已被用户使用。
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
