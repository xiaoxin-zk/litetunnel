package service

import (
	"errors"
	"testing"
)

// TestParseEmailDomainRules 覆盖写法归一与去重。
//
// 关键点：@qq.com 与 qq.com 必须等价（否则管理员按截图填 @qq.com 会得到
// 一条永远匹配不上任何邮箱的规则），全角逗号也要能切开。
func TestParseEmailDomainRules(t *testing.T) {
	rules, bad := ParseEmailDomainRules(" @qq.com, 163.com ,*.edu.cn，mailinator.com，QQ.COM ")
	if len(bad) != 0 {
		t.Fatalf("不该出现非法项: %v", bad)
	}
	if len(rules) != 4 {
		t.Fatalf("应得到 4 条规则（@qq.com 与 QQ.COM 去重），实际 %d: %v", len(rules), rules)
	}
	got := make(map[string]bool, len(rules))
	for _, r := range rules {
		got[r.String()] = true
	}
	for _, want := range []string{"@qq.com", "@163.com", "*.edu.cn", "@mailinator.com"} {
		if !got[want] {
			t.Errorf("缺少规则 %s，实际 %v", want, got)
		}
	}
}

// TestEmailDomainRuleMatch 覆盖子域包含关系。
//
// @qq.com 必须同时匹配 mail.qq.com：企业把自有域名列入白名单后，员工用
// mail.企业域名 注册是很常见的情况。*.edu.cn 则相反，只匹配子域。
func TestEmailDomainRuleMatch(t *testing.T) {
	suffix := EmailDomainRule{Suffix: "qq.com"}
	if !suffix.Match("qq.com") || !suffix.Match("mail.qq.com") || !suffix.Match("QQ.COM") {
		t.Error("@qq.com 应匹配本域与其子域")
	}
	if suffix.Match("foxmail.com") || suffix.Match("nqq.com") {
		t.Error("@qq.com 不该匹配其它域名")
	}

	wildcard := EmailDomainRule{Suffix: "edu.cn", Wildcard: true}
	if !wildcard.Match("pku.edu.cn") || !wildcard.Match("a.pku.edu.cn") {
		t.Error("*.edu.cn 应匹配子域")
	}
	if wildcard.Match("edu.cn") {
		t.Error("*.edu.cn 不该匹配 edu.cn 本身")
	}
}

// TestParseEmailDomainRulesRejectsGarbage 覆盖「静默丢弃」这个旧毛病。
//
// 以前解析不了的项会被悄悄扔掉，界面上看着保存成功、实际不生效。
// 现在必须把原始项交回给调用方，由保存路径报错。
func TestParseEmailDomainRulesRejectsGarbage(t *testing.T) {
	rules, bad := ParseEmailDomainRules("http://qq.com, qq.com:8080, localhost, *, @, qq.com/path")
	if len(rules) != 0 {
		t.Fatalf("这些项都不该被接受，实际解析出 %v", rules)
	}
	if len(bad) != 6 {
		t.Fatalf("应报出 6 个非法项，实际 %d: %v", len(bad), bad)
	}
}

// TestRegistrationDomainKey 覆盖「子域绕过单域名限额」。
//
// 直接按完整域名计数时，a.qq.com 与 b.qq.com 各算一份额度，换几个前缀就能
// 把「每域名每天 5 条」变成无限条。
func TestRegistrationDomainKey(t *testing.T) {
	cases := map[string]string{
		"a@mail.qq.com":        "qq.com",
		"b@qq.com":             "qq.com",
		"c@student.pku.edu.cn": "pku.edu.cn",
		"d@example.com":        "example.com",
		"":                     "",
		"not-an-email":         "",
	}
	for email, want := range cases {
		if got := RegistrationDomainKey(email); got != want {
			t.Errorf("RegistrationDomainKey(%q) = %q，期望 %q", email, got, want)
		}
	}
}

// TestCheckEmailDomainAdmissionWhitelistOnly 覆盖端到端的白名单判定。
func TestCheckEmailDomainAdmissionWhitelistOnly(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterAllowDomains:  "@qq.com",
		KeyRegisterWhitelistOnly: "true",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}

	if err := svc.checkEmailDomainAdmission("a@qq.com"); err != nil {
		t.Fatalf("白名单域名应放行: %v", err)
	}
	if err := svc.checkEmailDomainAdmission("a@mail.qq.com"); err != nil {
		t.Fatalf("白名单域名的子域应放行: %v", err)
	}
	if err := svc.checkEmailDomainAdmission("a@gmail.com"); !errors.Is(err, ErrDomainNotTrusted) {
		t.Fatalf("非白名单域名应被拒，实际 %v", err)
	}

	// 黑名单优先级更高：即使关掉白名单模式，命中黑名单也必须拒绝。
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterBlockDomains:  "mail.qq.com",
		KeyRegisterWhitelistOnly: "false",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	if err := svc.checkEmailDomainAdmission("a@mail.qq.com"); !errors.Is(err, ErrEmailNotAllowed) {
		t.Fatalf("黑名单域名应被拒，实际 %v", err)
	}
}

// TestSendEmailCodeRejectsNonWhitelistedDomain 覆盖「发码就拦」。
//
// 只在校验注册时才判断的话，用户要填完密码才被告知域名不允许，
// 看起来就像白名单没有生效。
func TestSendEmailCodeRejectsNonWhitelistedDomain(t *testing.T) {
	svc, fm := newMailTestServices(t)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterAllowDomains:  "@qq.com",
		KeyRegisterWhitelistOnly: "true",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}

	if err := svc.SendEmailCode("someone@gmail.com", EmailSceneRegister, "127.0.0.1"); !errors.Is(err, ErrDomainNotTrusted) {
		t.Fatalf("非白名单邮箱发码应被拒，实际 %v", err)
	}
	if n := fm.sentCount(); n != 0 {
		t.Fatalf("被拒的请求不该发出任何邮件，实际 %d 封", n)
	}
	if err := svc.SendEmailCode("someone@qq.com", EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("白名单邮箱发码应成功: %v", err)
	}
}

// TestUpdateSettingsRejectsBadDomainItem 覆盖保存阶段的严格校验。
func TestUpdateSettingsRejectsBadDomainItem(t *testing.T) {
	svc := newTestServices(t, nil)
	err := svc.UpdateSettings(map[SettingKey]string{
		KeyRegisterAllowDomains: "qq.com:8080",
	})
	if err == nil {
		t.Fatal("带端口的域名项应被拒绝保存")
	}
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("错误应可判定为参数不合法，实际 %v", err)
	}
}
