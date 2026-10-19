package main

import (
	"strings"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	const secret = "super-secret-token"
	got := redactSecret(secret, "调用失败: token "+secret+" 无效")
	if strings.Contains(got, secret) {
		t.Fatalf("密钥必须被抹掉，实际: %s", got)
	}
	if got := redactSecret("ab", "abcabc"); got != "abcabc" {
		t.Fatalf("过短的密钥不该参与替换: %s", got)
	}
}
