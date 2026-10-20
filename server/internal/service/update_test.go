package service

import (
	"errors"
	"strings"
	"testing"
)

// 404 不是「地址写错」，而是没有已发布的 Release：错误文案必须说清楚，
// 否则管理员只会看到「GitHub 返回 404」而无从下手。
func TestUpdateHTTPErrorMessages(t *testing.T) {
	cases := []struct {
		status   int
		remain   string
		contains string
	}{
		{404, "", "还没有已发布的 Release"},
		{401, "", "令牌无效或已过期"},
		{403, "0", "速率限制已用尽"},
		{403, "12", "拒绝了请求"},
		{429, "0", "速率限制已用尽"},
		{502, "", "GitHub 返回 502"},
	}
	for _, c := range cases {
		err := updateHTTPError("owner/repo", c.status, c.remain)
		if !errors.Is(err, ErrUpdateCheckFailed) {
			t.Fatalf("status=%d 应包装 ErrUpdateCheckFailed，实际 %v", c.status, err)
		}
		if !strings.Contains(err.Error(), c.contains) {
			t.Errorf("status=%d 文案应包含 %q，实际 %q", c.status, c.contains, err.Error())
		}
	}
}

func TestParseVersionTuple(t *testing.T) {
	cases := map[string]bool{
		"v1.2.3":      true,
		"1.2":         true,
		"0.1.121":     true,
		"v0.1.121":    true,
		"dev":         false,
		"ci-abc123":   false,
		"main-1a2b":   false,
		"v1.2.3-rc.1": true,
		"":            false,
		"one.two":     false,
	}
	for in, want := range cases {
		if _, ok := parseVersionTuple(in); ok != want {
			t.Fatalf("parseVersionTuple(%q) 可解析 = %v，期望 %v", in, ok, want)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		current, latest string
		less            bool
		comparable      bool
	}{
		{"0.1.10", "0.1.11", true, true},
		{"0.1.11", "0.1.11", false, true},
		{"0.2.0", "0.1.99", false, true},
		{"v0.1.9", "v0.1.10", true, true},
		{"1.0", "1.0.0", false, true},
		{"dev", "0.1.121", false, false},
		{"ci-abc1234", "0.1.121", false, false},
	}
	for _, c := range cases {
		less, comparable := versionLess(c.current, c.latest)
		if less != c.less || comparable != c.comparable {
			t.Fatalf("versionLess(%q, %q) = (%v,%v)，期望 (%v,%v)",
				c.current, c.latest, less, comparable, c.less, c.comparable)
		}
	}
}
