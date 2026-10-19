package main

import "testing"

// TestValidPanelDomainAllowsPort 覆盖「面板保存通过、下发必然失败」的分叉。
//
// 面板侧「面板域名」的默认值来自 LT_USER_PUBLIC_URL，可以带端口；helper 若
// 坚持只收裸域名，同一份配置保存时不报错，点「保存并应用」却报出一个与所填
// 内容对不上的错误。
func TestValidPanelDomainAllowsPort(t *testing.T) {
	for _, ok := range []string{
		"panel.example.com",
		"203.0.113.10:7848",
		"panel.example.com:8443",
	} {
		if err := validPanelDomain(ok); err != nil {
			t.Fatalf("%q 应被判为合法: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"panel.example.com:",
		"panel.example.com:0",
		"panel.example.com:70000",
		"panel.example.com:abc",
		"panel.example.com:7848/x",
		"2001:db8::1",
	} {
		if err := validPanelDomain(bad); err == nil {
			t.Fatalf("%q 应被判为非法", bad)
		}
	}
}
