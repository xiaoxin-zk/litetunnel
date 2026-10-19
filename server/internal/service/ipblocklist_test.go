package service

import (
	"net/netip"
	"testing"
)

func TestParseBlocklist(t *testing.T) {
	raw := `
# 注释行
203.0.113.7
10.0.0.0/8
2001:db8::/32
not-an-ip
10.0.0.0/99
`
	valid, invalid := ParseBlocklist(raw)
	if len(valid) != 3 {
		t.Fatalf("应识别 3 条合法规则，实际 %v", valid)
	}
	if len(invalid) != 2 {
		t.Fatalf("应识别 2 条非法规则，实际 %v", invalid)
	}
}

func TestBlockedPrefixesMatch(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyIPBlacklist: "203.0.113.7\n10.0.0.0/8\n",
	}); err != nil {
		t.Fatalf("保存黑名单失败: %v", err)
	}

	prefixes := svc.BlockedPrefixes()
	if len(prefixes) != 2 {
		t.Fatalf("应解析出 2 条规则，实际 %d 条", len(prefixes))
	}

	match := func(s string) bool {
		addr := netip.MustParseAddr(s)
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	if !match("10.20.30.40") {
		t.Fatal("网段内的地址应命中")
	}
	if !match("203.0.113.7") {
		t.Fatal("单 IP 规则应命中")
	}
	if match("8.8.8.8") {
		t.Fatal("不在名单内的地址不该命中")
	}

	// 清空后应立刻失效（缓存按原始文本比对）。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyIPBlacklist: ""}); err != nil {
		t.Fatalf("清空黑名单失败: %v", err)
	}
	if got := svc.BlockedPrefixes(); len(got) != 0 {
		t.Fatalf("清空后不应再有规则，实际 %v", got)
	}
}
