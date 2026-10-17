package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「先计数、后写入」留下的并发缺口。
//
// 注册的 IP / 域名额度，以及发验证码的冷却与每日上限，原先都是「查一次
// 计数、通过就写」。并发请求会同时读到「还没满」而各自落地；分布式来源
// 又能绕过单 IP 令牌桶。现在的做法是**预留后复核**：写进去之后把自己也
// 算上再判一次，超了就把这一笔撤掉。

// TestOverLimitSemantics 钉住两个口径的边界。
//
// inclusive 表示统计里包含刚写入的那条：恰好等于上限是正常的，
// 只有超过才回滚。两者混用会让每天都多放（或误杀）恰好一条记录，
// 而这种现象只看日志根本发现不了。
func TestOverLimitSemantics(t *testing.T) {
	cases := []struct {
		name      string
		n         int64
		limit     int
		inclusive bool
		want      bool
	}{
		{"预留后恰好达到上限", 3, 3, true, false},
		{"预留后超过上限", 4, 3, true, true},
		{"前置检查恰好达到上限", 3, 3, false, true},
		{"前置检查未达上限", 2, 3, false, false},
		{"不限量", 100, 0, true, false},
	}
	for _, tc := range cases {
		if got := overLimit(tc.n, tc.limit, tc.inclusive); got != tc.want {
			t.Fatalf("%s: overLimit(%d,%d,%v)=%v，期望 %v",
				tc.name, tc.n, tc.limit, tc.inclusive, got, tc.want)
		}
	}
}

// TestRegisterEnforcesDomainLimit 覆盖域名每日额度端到端生效。
//
// 同时守住预留口径的反面：库里已经 limit-1 个时注册必须成功
// （把自己算进去正好等于 limit），不能因为预留复核而误杀。
func TestRegisterEnforcesDomainLimit(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterMaxPerDomain: "1",
		KeyRegisterMaxPerIP:     "0", // 本用例只看域名维度
		KeyRegisterCaptcha:      "false",
	}); err != nil {
		t.Fatalf("设置限额失败: %v", err)
	}

	if _, err := svc.Register(RegisterInput{
		Username: "domainone", Password: "Passw0rd123",
		Email: "a@example.com", AgreedTerms: true, IP: "127.0.0.1",
	}); err != nil {
		t.Fatalf("第一个账号应注册成功（恰好达到上限）：%v", err)
	}

	_, err := svc.Register(RegisterInput{
		Username: "domaintwo", Password: "Passw0rd123",
		Email: "b@example.com", AgreedTerms: true, IP: "127.0.0.1",
	})
	if !errors.Is(err, ErrDomainRegisterLimited) {
		t.Fatalf("同域名第二个账号应被拒绝，实际 %v", err)
	}

	// 被拒绝的那个不能留下半条记录。
	var n int64
	if err := svc.DB.Model(&model.User{}).
		Where("username = ?", "domaintwo").Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("超限时注册必须整体回滚，不能留下用户记录")
	}
}

// TestRecheckEmailCodeQuotaRejectsConcurrentSend 覆盖「并发发码绕过冷却」。
//
// 前置的冷却与每日上限都是先查后写，两封同时进来会都通过。入队后复核
// 把刚写入的那封也算进去，超了就让调用方把它作废。
func TestRecheckEmailCodeQuotaRejectsConcurrentSend(t *testing.T) {
	svc := newTestServices(t, nil)

	const to = "quotarace@example.com"
	now := time.Now()
	mk := func(createdAt time.Time) *model.MailOutbox {
		row := &model.MailOutbox{
			To: to, Subject: "s", Kind: model.MailKindEmailCodeReset,
			Status: model.MailPending, NextAt: now, CreatedAt: createdAt,
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("建待发邮件失败: %v", err)
		}
		return row
	}

	// 场景一：冷却窗口内又发了一封。
	mk(now)
	second := mk(now)
	if err := svc.recheckEmailCodeQuota(second); !errors.Is(err, ErrEmailCodeTooSoon) {
		t.Fatalf("冷却窗口内的第二封应被作废，实际 %v", err)
	}

	// 场景二：当日总量超过上限（用较早的时间避开冷却是另一回事，
	// 这里让所有行都早于冷却窗口）。
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	old := dayStart.Add(time.Minute)
	for i := int64(0); i < emailCodeDailyPerEmail; i++ {
		mk(old)
	}
	last := mk(old)
	if err := svc.recheckEmailCodeQuota(last); !errors.Is(err, ErrEmailCodeTooMany) {
		t.Fatalf("超过每日上限应作废，实际 %v", err)
	}
}
