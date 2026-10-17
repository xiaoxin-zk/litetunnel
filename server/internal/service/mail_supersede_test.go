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

// mkResetLinkRow 构造一封「重置链接」发件箱记录（已送达、待激活），
// 并把入队时间（created_at）显式改到一分钟前：
// 取代判定比较的是 created_at，而 SQLite 的时间精度是秒级，
// 「稍后插入」不足以让 created_at 严格更大。
func mkResetLinkRow(t *testing.T, svc *Services, userID uint, hash string) model.MailOutbox {
	t.Helper()
	raw, err := json.Marshal(resetLinkPayload{UserID: userID, TokenHash: hash, TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	row := model.MailOutbox{
		To:      "supersede@example.com",
		Subject: "s",
		Kind:    model.MailKindResetLink,
		Payload: string(raw),
		Status:  model.MailDelivered,
		NextAt:  time.Now().Add(-time.Second),
	}
	if err := svc.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Update("created_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	// 重新读回，让调用方拿到更新后的 created_at。
	if err := svc.DB.First(&row, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func resetTokenCount(t *testing.T, svc *Services, where string, args ...any) int64 {
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
// 新邮件先一步送达并激活成功。此时旧动作重试若照常执行，「作废全部未使用
// 令牌 + 建旧令牌」会让用户手里最新的链接失效、反而复活最旧的——
// 正确行为是旧动作整体放弃。
func TestResetTokenActionSupersededByNewer(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "supersede", Password: "not-used", Status: model.UserStatusActive,
		Email: "supersede@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 较早的邮件 A（一分钟前入队）。
	rowA := mkResetLinkRow(t, svc, u.ID, "hash-old")
	// 较新的邮件 B 已送达并激活成功：库里有它的未使用令牌。
	tokB := model.PasswordResetToken{UserID: u.ID, TokenHash: "hash-new",
		ExpireAt: time.Now().Add(time.Hour)}
	if err := svc.DB.Create(&tokB).Error; err != nil {
		t.Fatal(err)
	}

	// 旧动作重试：必须识别「已被取代」，跳过激活。
	if err := svc.applyMailAction(rowA); err == nil {
		t.Fatal("旧邮件的激活应报告被取代，而不是静默成功")
	}

	if got := resetTokenCount(t, svc, "token_hash = ?", "hash-old"); got != 0 {
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

// TestMailActionReplayIdempotent 覆盖「动作重放幂等」。
//
// 激活成功但写终态失败时，下一轮会按原参数重放同一动作：
// 凭据仍在（未使用、同一摘要）就必须直接按成功处理，不能重复建记录——
// 否则同一条重置链接在库里会有多份，行为说不清。
func TestMailActionReplayIdempotent(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "replay", Password: "not-used", Status: model.UserStatusActive,
		Email: "replay@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	row := mkResetLinkRow(t, svc, u.ID, "hash-once")

	if err := svc.applyMailAction(row); err != nil {
		t.Fatalf("首次激活应成功: %v", err)
	}
	// 重放：不刷新任何状态，直接再执行一遍。
	if err := svc.applyMailAction(row); err != nil {
		t.Fatalf("重放应幂等成功: %v", err)
	}
	if got := resetTokenCount(t, svc, "token_hash = ?", "hash-once"); got != 1 {
		t.Fatalf("重放不得重复建令牌，实际 %d 条", got)
	}
}

// TestEmailCodeActionSupersededByNewer 覆盖验证码的同类取代判定。
//
// 与重置链接同一竞态：较早邮件的激活重试不得作废较新邮件刚生效的验证码。
func TestEmailCodeActionSupersededByNewer(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "codesupersede@example.com"

	mkRow := func(hash string) model.MailOutbox {
		t.Helper()
		raw, err := json.Marshal(emailCodePayload{Email: email, Scene: "reset",
			CodeHash: hash, TTLSeconds: 600})
		if err != nil {
			t.Fatal(err)
		}
		return model.MailOutbox{To: email, Subject: "s", Kind: model.MailKindEmailCodeReset,
			Payload: string(raw), Status: model.MailDelivered,
			NextAt: time.Now().Add(-time.Second)}
	}
	rowOld := mkRow("code-hash-old")
	if err := svc.DB.Create(&rowOld).Error; err != nil {
		t.Fatal(err)
	}
	// 同 reset link 的理由：把入队时间显式压到一分钟前。
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", rowOld.ID).
		Update("created_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.First(&rowOld, rowOld.ID).Error; err != nil {
		t.Fatal(err)
	}
	// 较新邮件已激活成功：它的验证码仍在。
	codeNew := model.EmailCode{Email: email, Scene: "reset", CodeHash: "code-hash-new",
		ExpireAt: time.Now().Add(time.Hour)}
	if err := svc.DB.Create(&codeNew).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.applyMailAction(rowOld); err == nil {
		t.Fatal("旧验证码邮件的激活应报告被取代")
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
	var still model.EmailCode
	if err := svc.DB.Where("code_hash = ?", "code-hash-new").First(&still).Error; err != nil {
		t.Fatalf("新验证码应仍在: %v", err)
	}
	if still.UsedAt != nil {
		t.Fatal("新验证码被旧邮件的重试作废了")
	}
}
