package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

func domainReject(svc *Services, email string) error {
	return svc.emailDomainVerdictFor(email).Reject
}

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

func TestEmailDomainRuleMatch(t *testing.T) {
	suffix := EmailDomainRule{Suffix: "qq.com"}
	if !suffix.Match("qq.com") || !suffix.Match("QQ.COM") {
		t.Error("@qq.com 应匹配本域")
	}
	if suffix.Match("s.qq.com") || suffix.Match("mail.qq.com") {
		t.Error("@qq.com 不该放行子域，子域必须显式写 *.qq.com")
	}
	if suffix.Match("foxmail.com") || suffix.Match("nqq.com") {
		t.Error("@qq.com 不该匹配其它域名")
	}

	wildcard := EmailDomainRule{Suffix: "qq.com", Wildcard: true}
	if !wildcard.Match("s.qq.com") || !wildcard.Match("a.mail.qq.com") {
		t.Error("*.qq.com 应匹配子域")
	}
	if !wildcard.Match("qq.com") {
		t.Error("*.qq.com 应同时匹配 qq.com 本身")
	}
}

func TestParseEmailDomainRulesRejectsGarbage(t *testing.T) {
	rules, bad := ParseEmailDomainRules("http://qq.com, qq.com:8080, localhost, *, @, qq.com/path")
	if len(rules) != 0 {
		t.Fatalf("这些项都不该被接受，实际解析出 %v", rules)
	}
	if len(bad) != 6 {
		t.Fatalf("应报出 6 个非法项，实际 %d: %v", len(bad), bad)
	}
}

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

func TestCheckEmailDomainAdmissionWhitelistOnly(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterAllowDomains:  "@qq.com",
		KeyRegisterWhitelistOnly: "true",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}

	if err := domainReject(svc, "a@qq.com"); err != nil {
		t.Fatalf("白名单域名应放行: %v", err)
	}
	if err := domainReject(svc, "a@s.qq.com"); !errors.Is(err, ErrDomainNotTrusted) {
		t.Fatalf("未写 *.qq.com 时子域应被拒，实际 %v", err)
	}
	if err := domainReject(svc, "a@gmail.com"); !errors.Is(err, ErrDomainNotTrusted) {
		t.Fatalf("非白名单域名应被拒，实际 %v", err)
	}

	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterAllowDomains: "*.qq.com",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	if err := domainReject(svc, "a@s.qq.com"); err != nil {
		t.Fatalf("*.qq.com 应放行子域: %v", err)
	}
	if err := domainReject(svc, "a@qq.com"); err != nil {
		t.Fatalf("*.qq.com 应同时放行 qq.com 本身: %v", err)
	}

	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterBlockDomains:  "mail.qq.com",
		KeyRegisterWhitelistOnly: "false",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	if err := domainReject(svc, "a@mail.qq.com"); !errors.Is(err, ErrEmailNotAllowed) {
		t.Fatalf("黑名单域名应被拒，实际 %v", err)
	}
}

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

func TestNonWhitelistQuota(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterAllowDomains:      "@company.com",
		KeyRegisterWhitelistOnly:     "true",
		KeyRegisterNonWhitelistQuota: "1",
		KeyRegisterRequireEmail:      "false",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}

	if v := svc.emailDomainVerdictFor("a@qq.com"); v.Reject != nil || v.Quota != 1 {
		t.Fatalf("白名单外域名应放量 1 个，实际 %+v", v)
	}
	if v := svc.emailDomainVerdictFor("a@company.com"); v.Reject != nil || v.Quota != 0 {
		t.Fatalf("白名单域名不该受配额约束，实际 %+v", v)
	}

	if _, err := svc.Register(RegisterInput{
		Username: "quotaone", Password: "Passw0rd123",
		Email: "first@qq.com", AgreedTerms: true, IP: "10.0.0.1",
	}); err != nil {
		t.Fatalf("首个白名单外账号应注册成功: %v", err)
	}
	if _, err := svc.Register(RegisterInput{
		Username: "quotatwo", Password: "Passw0rd123",
		Email: "second@qq.com", AgreedTerms: true, IP: "10.0.0.2",
	}); !errors.Is(err, ErrNonWhitelistQuota) {
		t.Fatalf("名额用尽后应拒绝，实际 %v", err)
	}
}

func TestGatewayEndpointPrefersSettings(t *testing.T) {
	svc := newTestServices(t, &config.Config{GatewayHost: "gw.example.com", GatewayPort: 7001})
	if h, p := svc.GatewayEndpoint(); h != "gw.example.com" || p != 7001 {
		t.Fatalf("未配置时应回落 .env，实际 %s:%d", h, p)
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyGatewayHost: "gw2.example.com",
		KeyGatewayPort: "7100",
	}); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	if h, p := svc.GatewayEndpoint(); h != "gw2.example.com" || p != 7100 {
		t.Fatalf("应使用后台设置值，实际 %s:%d", h, p)
	}
}
