package main

import (
	"strings"
	"testing"
)

// 这个文件守一条底线：**长期 API Key 不能走明文 HTTP**。
//
// 接入之后每一轮同步都带着 API Key，而它是「泄露一次、长期可用」的凭据。
// 明文链路上的任何一跳都能抄走它，然后以该用户身份接入隧道。
// 因此地址校验必须发生在填地址的那一刻，而不是等到请求发出去。

func TestCheckServerURLRequiresHTTPSForRemoteHosts(t *testing.T) {
	// 远程地址：只认 https，写成 http 时必须在填地址阶段就被拒绝。
	for _, raw := range []string{
		"http://panel.example.com",
		"http://203.0.113.10:7848",
		"http://[2001:db8::1]:7848",
	} {
		if _, err := checkServerURL(raw, false); err == nil {
			t.Errorf("%s 是明文远程地址，必须拒绝", raw)
		}
	}

	ok, err := checkServerURL("https://panel.example.com", false)
	if err != nil {
		t.Fatalf("https 地址不该被拒绝: %v", err)
	}
	if ok != "https://panel.example.com" {
		t.Fatalf("地址应原样返回，得到 %q", ok)
	}
}

func TestCheckServerURLAllowsLoopbackPlaintextOnlyForDebug(t *testing.T) {
	// 本地调试：链路不出本机，允许 http。
	for _, raw := range []string{
		"http://127.0.0.1:7848",
		"http://localhost:7848",
		"http://[::1]:7848",
	} {
		if _, err := checkServerURL(raw, false); err != nil {
			t.Errorf("%s 是本机地址，调试构建下应允许: %v", raw, err)
		}
	}

	// 构建注入的地址一律要求 https：正式客户端的内置地址写成 http://IP，
	// 等于把 API Key 明文发给链路上的所有人。这里选择「拒绝启动连接」，
	// 而不是「照发凭据」。
	if _, err := checkServerURL("http://127.0.0.1:7848", true); err == nil {
		t.Error("构建注入的地址即使是本机地址也必须是 https")
	}
}

func TestCheckServerURLNormalizesAndRejectsGarbage(t *testing.T) {
	// 没写协议时按 https 补全：默认走加密，而不是默认走明文。
	got, err := checkServerURL("panel.example.com", false)
	if err != nil {
		t.Fatalf("未写协议时应按 https 处理: %v", err)
	}
	if got != "https://panel.example.com" {
		t.Fatalf("应补成 https://，得到 %q", got)
	}

	// 结尾斜杠去掉：否则拼出来的路径会多一层。
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

// TestServerBaseRefusesStoredPlaintextURL 覆盖升级路径：早期版本允许把
// http:// 公网地址存进本地配置，那份配置可能还在磁盘上。升级后必须拒绝它，
// 否则明文凭据会一直发下去，而用户看到的只是一句「同步失败」。
func TestServerBaseRefusesStoredPlaintextURL(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制配置")
	}

	a := &App{cfg: &Config{APIKey: "lt_test_key", ServerURL: "http://panel.example.com"}}
	if got := a.serverBase(); got != "" {
		t.Fatalf("保存的明文公网地址不该被采用，得到 %q", got)
	}
	// 原因必须说清楚：只说「尚未接入」的话，用户怎么点连接都没用。
	if reason := a.baseReason(); !strings.Contains(reason, "已保存的服务器地址不可用") {
		t.Fatalf("应当说明是保存的地址不可用，实际 %q", reason)
	}

	// 本机调试地址仍然可用，否则本地开发全被挡住。
	debug := &App{cfg: &Config{APIKey: "lt_test_key", ServerURL: "http://127.0.0.1:7848"}}
	if got := debug.serverBase(); got != "http://127.0.0.1:7848" {
		t.Fatalf("本机调试地址应当可用，得到 %q", got)
	}
	if _, _, err := debug.currentCredential(); err != nil {
		t.Fatalf("本机调试地址应当能取到凭据: %v", err)
	}
}
