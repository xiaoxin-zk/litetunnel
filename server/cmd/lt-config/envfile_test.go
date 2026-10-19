package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func TestEnvValueEscapingRoundTrip(t *testing.T) {
	values := []string{
		"plain-token",
		"tok$en",
		"a${LT_CADDY_IMAGE}b",
		"$NAME",
		"pass word",
		"a#b",
		"a # b",
		`he said "hi"`,
		`back\slash`,
		"it's",
		"中文$值",
		"line$$dollar",
		"a\tb",
	}
	for _, v := range values {
		encoded := encodeEnvValue(v)
		if got := decodeEnvValue(encoded); got != v {
			t.Errorf("往返不一致: %q → %q → %q", v, encoded, got)
		}
	}
}

func TestEncodeEnvValueEscapesDollarForCompose(t *testing.T) {
	if got := encodeEnvValue("tok$en"); got != "tok$$en" {
		t.Fatalf("裸值里的 $ 应写成 Compose 的转义插值 $$，实际 %q", got)
	}
	if got := encodeEnvValue(`a"b`); got != `"a\"b"` {
		t.Fatalf("含双引号的值应加引号并转义，实际 %q", got)
	}
	if got := encodeEnvValue("a b"); got != `"a b"` {
		t.Fatalf("含空白的值应加引号，实际 %q", got)
	}
	if got := encodeEnvValue("plain"); got != "plain" {
		t.Fatalf("普通值不该被改动，实际 %q", got)
	}
}

func TestEnvFileSetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("LT_CADDY_IMAGE=ghcr.io/ok/caddy:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env, _, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	const credential = `tok$en "quoted" # note`
	if _, err := env.set(tlscfg.VarDNSCredential, credential); err != nil {
		t.Fatalf("写入凭据失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(env.content()), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsLine(string(raw), `LT_CADDY_DNS_CREDENTIAL="tok$$en \"quoted\" # note"`) {
		t.Fatalf(".env 里的值未按 Compose 规则编码:\n%s", raw)
	}

	_, vars, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := vars[tlscfg.VarDNSCredential]; got != credential {
		t.Fatalf("读回的值应与写入的原始值一致，实际 %q（期望 %q）", got, credential)
	}
	if got := vars["LT_CADDY_IMAGE"]; got != "ghcr.io/ok/caddy:1" {
		t.Fatalf("无关行不应被改动，实际 %q", got)
	}
}

func containsLine(haystack, needle string) bool {
	for _, l := range splitLines(haystack) {
		if l == needle {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > start && s[end-1] == '\r' {
				end--
			}
			out = append(out, s[start:end])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
