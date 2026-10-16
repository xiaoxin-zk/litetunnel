package main

import (
	"strings"
	"testing"
)

// TestRedactSecret 守住「把凭据回显给浏览器」这条路。
//
// 服务商插件在凭据无效时会把凭据本身打进错误里，而这段文本会经面板显示在
// 浏览器上——也就进了截图、工单与聊天记录。
func TestRedactSecret(t *testing.T) {
	const secret = "super-secret-token"
	got := redactSecret(secret, "调用失败: token "+secret+" 无效")
	if strings.Contains(got, secret) {
		t.Fatalf("密钥必须被抹掉，实际: %s", got)
	}
	// 过短的值不做替换：那会把正常文本打得满目疮痍。
	if got := redactSecret("ab", "abcabc"); got != "abcabc" {
		t.Fatalf("过短的密钥不该参与替换: %s", got)
	}
}
