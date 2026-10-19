package service

import (
	"net/netip"
	"strings"
	"time"
)

const ipBlocklistCacheTTL = 30 * time.Second

// BlockedPrefixes 解析后台维护的 IP / CIDR 黑名单。
// 支持每行一个条目、# 注释与 IPv6；非法行直接跳过，避免一处写错让整条规则失效。
func (s *Services) BlockedPrefixes() []netip.Prefix {
	s.blockMu.Lock()
	defer s.blockMu.Unlock()

	raw := strings.TrimSpace(s.Settings.Get(KeyIPBlacklist))
	if raw == "" {
		s.blockCache = nil
		s.blockRaw = ""
		return nil
	}
	if raw == s.blockRaw && time.Since(s.blockAt) < ipBlocklistCacheTTL {
		return s.blockCache
	}

	prefixes := make([]netip.Prefix, 0, 16)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if p, err := netip.ParsePrefix(line); err == nil {
				prefixes = append(prefixes, p.Masked())
			}
			continue
		}
		if addr, err := netip.ParseAddr(line); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	s.blockRaw = raw
	s.blockCache = prefixes
	s.blockAt = time.Now()
	return prefixes
}

// ParseBlocklist 供设置保存时做校验。
func ParseBlocklist(raw string) (valid []string, invalid []string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if _, err := netip.ParsePrefix(line); err == nil {
				valid = append(valid, line)
				continue
			}
		} else if _, err := netip.ParseAddr(line); err == nil {
			valid = append(valid, line)
			continue
		}
		invalid = append(invalid, line)
	}
	return valid, invalid
}
