package service

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// 邮箱域名准入策略：白名单、黑名单与「单域名限额」计数口径的唯一入口。
//
// 结构对齐 sub2api 的 registrationEmailPolicy：列表项在**解析时**就规范化
//
//	@domain   精确匹配该域本身，不含子域
//	*.domain  只匹配子域，不含本域
//
// 并且把无法识别的项**报出来**，而不是静默丢掉。静默丢弃的代价最隐蔽：
// 少打一个字符的结果是「界面上看着保存了、实际永远不生效」，而且没有任何
// 提示——用户只会得出「白名单没用」这个结论。
//
// 把规范化集中在解析阶段，也顺手消除了一处历史分叉：黑名单自己剥 @、
// 白名单走另一套解析，同一份配置在两处会按不同规则解释。

// EmailDomainRule 是一条规范化后的邮箱域名规则。
type EmailDomainRule struct {
	// Suffix 是不带通配符的域名，例如 qq.com。
	Suffix string
	// Wildcard 为 true 表示 *.domain：只匹配子域，不匹配本域。
	Wildcard bool
}

// String 回显规范化后的写法，供管理端展示与错误信息使用。
func (r EmailDomainRule) String() string {
	if r.Wildcard {
		return "*." + r.Suffix
	}
	return "@" + r.Suffix
}

// Match 判断邮箱域名是否命中本规则。
//
// 两条规则的边界很硬：@qq.com 只认 qq.com，*.qq.com 只认子域。子域不会被
// 自动放行——白名单一旦自动包含子域，管理员写下的「只允许 qq.com」实际会变成
// 「允许 qq.com 及任何 s.qq.com」，与他的意图相反。
func (r EmailDomainRule) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || r.Suffix == "" {
		return false
	}
	if r.Wildcard {
		return strings.HasSuffix(domain, "."+r.Suffix)
	}
	// 精确匹配，**不含子域**。
	//
	// 白名单写 @qq.com 就只放行 qq.com 本身：子域太容易被第三方接管
	// （s.qq.com 这类地址既不是 QQ 邮箱官方的，也不受本平台控制），
	// 因为它自动包含子域，等于把白名单悄悄放大了。要放行子域必须显式写
	// *.your-domain.com。
	return domain == r.Suffix
}

// ParseEmailDomainRules 解析逗号（含全角）与空白分隔的域名列表。
//
// 返回值第二项是无法识别的原始项：保存路径应当把它当错误上报，运行期读取
// 则忽略——配置写坏了也不该让注册接口 500。
func ParseEmailDomainRules(raw string) ([]EmailDomainRule, []string) {
	var rules []EmailDomainRule
	var bad []string
	seen := make(map[string]bool)
	for _, part := range splitEmailDomainList(raw) {
		rule, ok := normalizeEmailDomainRule(part)
		if !ok {
			bad = append(bad, part)
			continue
		}
		key := rule.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, rule)
	}
	return rules, bad
}

// splitEmailDomainList 按逗号与空白切分，兼容管理端整段粘贴的写法。
func splitEmailDomainList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
}

// normalizeEmailDomainRule 把一条原始项规范化成规则。
//
// 接受 qq.com、@qq.com、*.qq.com、QQ.COM。其余一律视为非法：带路径、
// 带端口、单段主机名（localhost）、裸通配符都无法作为邮箱域名使用。
func normalizeEmailDomainRule(part string) (EmailDomainRule, bool) {
	part = strings.ToLower(strings.TrimSpace(part))
	if part == "" {
		return EmailDomainRule{}, false
	}
	wildcard := false
	if strings.HasPrefix(part, "*.") {
		wildcard = true
		part = strings.TrimPrefix(part, "*.")
	} else if strings.HasPrefix(part, "*") {
		return EmailDomainRule{}, false
	}
	part = strings.TrimPrefix(part, "@")
	part = strings.TrimSuffix(part, ".")
	if part == "" || strings.ContainsAny(part, " \t\r\n/\\:@*?") {
		return EmailDomainRule{}, false
	}
	if !strings.Contains(part, ".") {
		return EmailDomainRule{}, false
	}
	for _, label := range strings.Split(part, ".") {
		if label == "" {
			return EmailDomainRule{}, false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return EmailDomainRule{}, false
		}
	}
	return EmailDomainRule{Suffix: part, Wildcard: wildcard}, true
}

// emailDomainIn 判断域名是否命中规则集。
func emailDomainIn(domain string, rules []EmailDomainRule) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, r := range rules {
		if r.Match(domain) {
			return true
		}
	}
	return false
}

// RegistrationDomainKey 返回「单域名每日上限」的计数键：公共后缀主域。
//
// 直接用完整邮箱域名计数会被子域绕过：a.qq.com 与 b.qq.com 各自算一份额度，
// 换几个前缀就能把「每域名每天 5 条」变成无限条。sub2api 同样按主域归一。
func RegistrationDomainKey(email string) string {
	domain := emailDomain(email)
	if domain == "" {
		return ""
	}
	if root, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil && root != "" {
		return root
	}
	// 私有后缀（内网域名等）拿不到主域时退回完整域名，总比空键好。
	return domain
}

// allowedEmailDomainRules 读取白名单规则。运行期容错：非法项忽略。
func (s *Services) allowedEmailDomainRules() []EmailDomainRule {
	rules, _ := ParseEmailDomainRules(s.Settings.Get(KeyRegisterAllowDomains))
	return rules
}

// blockedEmailDomainRules 读取黑名单规则。
func (s *Services) blockedEmailDomainRules() []EmailDomainRule {
	rules, _ := ParseEmailDomainRules(s.Settings.Get(KeyRegisterBlockDomains))
	return rules
}

// isTrustedEmailDomain 判断邮箱域名是否命中白名单（可信域名，可跳过限额）。
func (s *Services) isTrustedEmailDomain(domain string) bool {
	return emailDomainIn(domain, s.allowedEmailDomainRules())
}

// checkEmailDomainAdmission 是注册与换绑共用的域名准入检查。
//
// 只对「即将落库的邮箱」调用。找回密码**不能**调用：那条路径对任何域名都要
// 返回同样的结果，否则接口会退化成账号枚举工具。
//
// 放在这里而不是只放在 Register 里，是因为发验证码时就能告诉用户
// 「这个域名不让注册」——等他填完密码再报错，只会让人以为验证码那步是坏的。
func (s *Services) checkEmailDomainAdmission(email string) error {
	domain := emailDomain(email)
	if domain == "" {
		return nil
	}
	if emailDomainIn(domain, s.blockedEmailDomainRules()) {
		return ErrEmailNotAllowed
	}
	if s.Settings.Bool(KeyRegisterWhitelistOnly) && !s.isTrustedEmailDomain(domain) {
		return ErrDomainNotTrusted
	}
	return nil
}
