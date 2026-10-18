package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 这个文件守的是 .env 值的「写出去的是什么、读回来的还是什么」。
//
// .env 会被 docker compose --env-file 解析：值先按 dotenv 语法解析、再做插值，
// 凭据里一个裸的 $（$NAME、${NAME}）都会被当作变量引用展开——运行时 Caddy
// 拿到的是另一个字符串，签不出证书还查不出原因。encodeEnvValue 按 Compose
// 的规则编码（$ → $$，必要时加引号），decodeEnvValue 与之互逆；
// 两者的往返必须是无损的，这里逐类字符验证。

func TestEnvValueEscapingRoundTrip(t *testing.T) {
	values := []string{
		"plain-token",
		"tok$en",              // 裸 $：会被 Compose 当变量引用
		"a${LT_CADDY_IMAGE}b", // 带花括号的完整引用
		"$NAME",               // 整段都是引用
		"pass word",           // 空白：未加引号会被两端去空白
		"a#b",                 // #：可能被解析成行内注释
		"a # b",               // 带空白的 #：注释起点
		`he said "hi"`,        // 双引号：破坏引号结构
		`back\slash`,          // 反斜杠：双引号内是转义符
		"it's",                // 单引号：破坏引号结构
		"中文$值",                // 多字节字符与 $ 混排
		"line$$dollar",        // 输入里就有 $$
		"a\tb",                // 制表符：同样破坏一行一个值
	}
	for _, v := range values {
		encoded := encodeEnvValue(v)
		if got := decodeEnvValue(encoded); got != v {
			t.Errorf("往返不一致: %q → %q → %q", v, encoded, got)
		}
		// 编码结果本身不能再含有裸的 $（都是 $$ 或在引号内被转义保护）。
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

// TestEnvFileSetRoundTrip 走完整链路：set 写盘 → readEnvFile 读回，
// 断言解析结果与写入的原始值一致，且文件行是 Compose 兼容的编码形式。
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
	// 文件里必须是编码后的形式：$ 已转义为 $$，值被引号保护。
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
	// 未被 set 碰过的行保持原样。
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
