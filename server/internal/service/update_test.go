package service

import "testing"

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
