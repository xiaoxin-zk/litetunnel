package main

import "testing"

func TestCheckServerURLAllowsRemoteHTTPWithWarning(t *testing.T) {
	for _, raw := range []string{"http://panel.example.com", "http://203.0.113.10:7848", "http://[2001:db8::1]:7848"} {
		if _, err := checkServerURL(raw, false); err != nil {
			t.Errorf("%s 应允许 HTTP: %v", raw, err)
		}
	}
}

func TestCheckServerURLAllowsHTTPSForRemoteHosts(t *testing.T) {
	ok, err := checkServerURL("https://panel.example.com", false)
	if err != nil {
		t.Fatalf("https 地址不该被拒绝: %v", err)
	}
	if ok != "https://panel.example.com" {
		t.Fatalf("地址应原样返回，得到 %q", ok)
	}
}

func TestCheckServerURLAllowsLoopbackPlaintextOnlyForDebug(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:7848",
		"http://localhost:7848",
		"http://[::1]:7848",
	} {
		if _, err := checkServerURL(raw, false); err != nil {
			t.Errorf("%s 是本机地址，调试构建下应允许: %v", raw, err)
		}
	}

	if _, err := checkServerURL("http://panel.example.com", true); err != nil {
		t.Fatalf("构建注入的 HTTP 地址应允许，但应由部署者承担明文风险: %v", err)
	}
}

func TestCheckServerURLNormalizesAndRejectsGarbage(t *testing.T) {
	got, err := checkServerURL("panel.example.com", false)
	if err != nil {
		t.Fatalf("未写协议时应按 https 处理: %v", err)
	}
	if got != "https://panel.example.com" {
		t.Fatalf("应补成 https://，得到 %q", got)
	}

	if got, _ := checkServerURL("https://panel.example.com/", false); got != "https://panel.example.com" {
		t.Fatalf("结尾斜杠应被去掉，得到 %q", got)
	}

	cases := []struct{ name, raw string }{
		{"空地址", ""},
		{"缺少主机名", "https://"},
		{"非 http(s) 协议", "ftp://panel.example.com"},
		{"解析失败", "https://[::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := checkServerURL(tc.raw, false); err == nil {
				t.Fatalf("%q 应当被拒绝", tc.raw)
			}
		})
	}
}

func TestServerBaseAcceptsStoredPlaintextURL(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制配置")
	}

	a := &App{cfg: &Config{APIKey: "lt_test_key", ServerURL: "http://panel.example.com"}}
	if got := a.serverBase(); got != "http://panel.example.com" {
		t.Fatalf("保存的公网 HTTP 地址应当可用，得到 %q", got)
	}
	if _, _, err := a.currentCredential(); err != nil {
		t.Fatalf("HTTP 地址也应当能取到凭据: %v", err)
	}

	debug := &App{cfg: &Config{APIKey: "lt_test_key", ServerURL: "http://127.0.0.1:7848"}}
	if got := debug.serverBase(); got != "http://127.0.0.1:7848" {
		t.Fatalf("本机调试地址应当可用，得到 %q", got)
	}
	if _, _, err := debug.currentCredential(); err != nil {
		t.Fatalf("本机调试地址应当能取到凭据: %v", err)
	}
}
