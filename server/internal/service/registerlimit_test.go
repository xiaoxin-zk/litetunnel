package service

import (
	"errors"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

func TestRegisterEnforcesDomainLimit(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterMaxPerDomain: "1",
		KeyRegisterMaxPerIP:     "0",
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

	var n int64
	if err := svc.DB.Model(&model.User{}).
		Where("username = ?", "domaintwo").Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("超限时注册必须整体回滚，不能留下用户记录")
	}
}

func TestEmailCodeQuotaEnforcedBeforeWrite(t *testing.T) {
	svc := newTestServices(t, nil)

	const to = "quotarace@example.com"
	now := time.Now()
	quota := mailQuota{cooldown: emailCodeResendCooldown, dailyLimit: emailCodeDailyPerEmail}
	mk := func(createdAt time.Time) {
		row := &model.MailOutbox{
			To: to, Subject: "s", Kind: model.MailKindEmailCodeReset,
			Status: model.MailPending, NextAt: now, CreatedAt: createdAt,
		}
		if err := svc.DB.Create(row).Error; err != nil {
			t.Fatalf("建待发邮件失败: %v", err)
		}
	}

	mk(now)
	if err := checkMailQuota(svc.DB, to, model.MailKindEmailCodeReset, quota); !errors.Is(err, errMailQuotaCooldown) {
		t.Fatalf("冷却窗口内应拒绝，实际 %v", err)
	}

	quota.cooldown = 0
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	old := dayStart.Add(time.Minute)
	if err := svc.DB.Model(&model.MailOutbox{}).
		Where("lower(to_addr) = ?", to).Update("created_at", old).Error; err != nil {
		t.Fatal(err)
	}
	for i := 1; i < emailCodeDailyPerEmail; i++ {
		mk(old)
	}
	if err := checkMailQuota(svc.DB, to, model.MailKindEmailCodeReset, quota); !errors.Is(err, errMailQuotaDaily) {
		t.Fatalf("达到每日上限应拒绝，实际 %v", err)
	}
}
