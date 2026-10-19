package service

import (
	"strings"

	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type EmailDomainRule struct {
	Suffix   string
	Wildcard bool
}

func (r EmailDomainRule) String() string {
	if r.Wildcard {
		return "*." + r.Suffix
	}
	return "@" + r.Suffix
}

func (r EmailDomainRule) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || r.Suffix == "" {
		return false
	}
	if r.Wildcard {
		return domain == r.Suffix || strings.HasSuffix(domain, "."+r.Suffix)
	}
	return domain == r.Suffix
}

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

func splitEmailDomainList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
}

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

func RegistrationDomainKey(email string) string {
	domain := emailDomain(email)
	if domain == "" {
		return ""
	}
	if root, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil && root != "" {
		return root
	}
	return domain
}

func (s *Services) allowedEmailDomainRules() []EmailDomainRule {
	rules, _ := ParseEmailDomainRules(s.Settings.Get(KeyRegisterAllowDomains))
	return rules
}

func (s *Services) blockedEmailDomainRules() []EmailDomainRule {
	rules, _ := ParseEmailDomainRules(s.Settings.Get(KeyRegisterBlockDomains))
	return rules
}

func (s *Services) isTrustedEmailDomain(domain string) bool {
	return emailDomainIn(domain, s.allowedEmailDomainRules())
}

type emailDomainVerdict struct {
	Reject error
	Quota  int
}

func (s *Services) emailDomainVerdictFor(email string) emailDomainVerdict {
	domain := emailDomain(email)
	if domain == "" {
		return emailDomainVerdict{}
	}
	if emailDomainIn(domain, s.blockedEmailDomainRules()) {
		return emailDomainVerdict{Reject: ErrEmailNotAllowed}
	}
	if !s.Settings.Bool(KeyRegisterWhitelistOnly) {
		return emailDomainVerdict{}
	}
	if len(s.allowedEmailDomainRules()) == 0 {
		return emailDomainVerdict{}
	}
	if s.isTrustedEmailDomain(domain) {
		return emailDomainVerdict{}
	}
	quota := s.Settings.Int(KeyRegisterNonWhitelistQuota)
	if quota <= 0 {
		return emailDomainVerdict{Reject: ErrDomainNotTrusted}
	}
	return emailDomainVerdict{Quota: quota}
}

func (s *Services) checkNonWhitelistQuota(db *gorm.DB, domain string, quota int) error {
	if domain == "" || quota <= 0 {
		return nil
	}
	var n int64
	if err := db.Model(&model.User{}).Where("email_domain = ?", domain).Count(&n).Error; err != nil {
		return nil
	}
	if n >= int64(quota) {
		return ErrNonWhitelistQuota
	}
	return nil
}
