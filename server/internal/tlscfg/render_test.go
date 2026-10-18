package tlscfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderDropsEmptyConditionalBlock 覆盖最要命的那条语义：
// 变量为空时整段删除，而不是留下一个空地址行——后者会让 Caddy
// 拒绝加载**整份** Caddyfile，也就是「一个可选项没填，整个反代起不来」。
func TestRenderDropsEmptyConditionalBlock(t *testing.T) {
	tpl := strings.Join([]string{
		"admin off",
		"# @if LT_TUNNEL_DOMAIN",
		"*.${LT_TUNNEL_DOMAIN} {",
		"\treverse_proxy 127.0.0.1:8081",
		"}",
		"# @endif",
		"",
	}, "\n")

	out, err := Render(tpl, map[string]string{"LT_TUNNEL_DOMAIN": ""})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(out, "@if") || strings.Contains(out, "reverse_proxy") {
		t.Fatalf("空值时应整段删除，实际得到:\n%s", out)
	}
	if !strings.Contains(out, "admin off") {
		t.Fatalf("条件块之外的文本被误删:\n%s", out)
	}

	out, err = Render(tpl, map[string]string{"LT_TUNNEL_DOMAIN": "t.example.com"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, "*.t.example.com {") {
		t.Fatalf("非空值时应保留并替换，实际得到:\n%s", out)
	}
}

// TestRenderNestedConditionals 嵌套时，外层丢弃必须连带内层一起丢弃。
func TestRenderNestedConditionals(t *testing.T) {
	tpl := "# @if A\nouter\n# @if B\ninner\n# @endif\n# @endif\n"

	out, err := Render(tpl, map[string]string{"A": "", "B": "x"})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(out, "outer") || strings.Contains(out, "inner") {
		t.Fatalf("外层为空时整段都该消失，实际:\n%s", out)
	}

	out, err = Render(tpl, map[string]string{"A": "x", "B": ""})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if !strings.Contains(out, "outer") || strings.Contains(out, "inner") {
		t.Fatalf("内层为空只该删内层，实际:\n%s", out)
	}
}

// TestRenderRejectsLeftoverPlaceholder 残留占位符必须直接失败。
//
// 这是「校验后应用」的第一道闸：宁可在渲染阶段报错，
// 也不要把一份 Caddy 拒绝加载的配置写进部署目录。
func TestRenderRejectsLeftoverPlaceholder(t *testing.T) {
	if _, err := Render("port = ${LT_MISSING_PORT}\n", map[string]string{}); err == nil {
		t.Fatal("残留占位符应导致渲染失败")
	}
}

// TestRenderPrefersLongerKeys 键名互为前缀时，必须长键先替换。
func TestRenderPrefersLongerKeys(t *testing.T) {
	out, err := Render("a=${LT_USER_PORT} b=${LT_USER_PORT_X}\n", map[string]string{
		"LT_USER_PORT":   "7848",
		"LT_USER_PORT_X": "1",
	})
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if out != "a=7848 b=1\n" {
		t.Fatalf("长键优先替换被破坏: %q", out)
	}
}

// TestRenderRealTemplates 用仓库里真实的模板跑一遍。
//
// 目的不是校验内容，而是让「模板新增了占位符、而调用方没给值」
// 这类问题在单测里就暴露——否则它只会在某台服务器重启 Caddy 时爆发。
func TestRenderRealTemplates(t *testing.T) {
	root := filepath.Join("..", "..", "..", "deploy")
	cases := []struct {
		file string
		vars map[string]string
	}{
		{
			file: "caddy/Caddyfile.template",
			vars: map[string]string{
				"LT_ACME_EMAIL":             "admin@example.com",
				"LT_USER_DOMAIN":            "panel.example.com",
				"LT_USER_PORT":              "7848",
				"LT_TUNNEL_DOMAIN":          "tunnel.example.com",
				"LT_CADDY_DNS_PROVIDER":     "cloudflare",
				"LT_CADDY_DNS_ARGS":         "{env.LT_CADDY_DNS_CREDENTIAL}",
				"LT_VHOST_HTTP_PORT":        "8081",
				"LT_VHOST_HTTPS_PORT":       "8444",
				"LT_HTTPS_E2E_PORT":         "8444",
				"LT_ADMIN_ALLOW_CIDR":       "127.0.0.1/32",
				"LT_USER_SCHEME":            "https",
				"LT_HSTS_ON":                "1",
				"LT_ACME_EMAIL_PLACEHOLDER": "",
			},
		},
		{
			file: "frps/frps.toml.template",
			vars: map[string]string{
				"LT_GATEWAY_PORT":       "7001",
				"LT_KCP_PORT":           "7002",
				"LT_VHOST_HTTP_PORT":    "8081",
				"LT_VHOST_HTTPS_PORT":   "8444",
				"LT_FRPS_TOKEN":         "x",
				"LT_PORT_RANGE_START":   "15000",
				"LT_PORT_RANGE_END":     "32767",
				"LT_MAX_PORTS_PER_USER": "20",
				"LT_TUNNEL_DOMAIN":      "tunnel.example.com",
				"LT_FRPS_API_PORT":      "7500",
				"LT_FRPS_API_USER":      "admin",
				"LT_FRPS_API_PASSWORD":  "x",
				"LT_USER_PORT":          "7848",
				"LT_HTTPS_E2E_PORT":     "8444",
			},
		},
	}

	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join(root, c.file))
		if err != nil {
			t.Skipf("跳过 %s：%v", c.file, err)
		}
		if _, err := Render(string(raw), c.vars); err != nil {
			t.Errorf("%s 渲染失败: %v", c.file, err)
		}
	}
}

// TestRenderCaddyHTTPMode 覆盖「没有域名证书的部署」。
//
// HTTP 站点不能发送 HSTS：那会让浏览器把后续请求强制升级到 https，
// 而该站点根本没有证书——表现就是「配置改对了却打不开」。
func TestRenderCaddyHTTPMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "caddy", "Caddyfile.template"))
	if err != nil {
		t.Skipf("跳过：%v", err)
	}
	vars := map[string]string{
		"LT_USER_DOMAIN":      "203.0.113.10",
		"LT_USER_SCHEME":      "http",
		"LT_HSTS_ON":          "",
		"LT_USER_PORT":        "7848",
		"LT_ACME_EMAIL":       "admin@example.com",
		"LT_ADMIN_ALLOW_CIDR": "127.0.0.1/32",
	}
	out, err := Render(string(raw), vars)
	if err != nil {
		t.Fatalf("HTTP 模板渲染失败: %v", err)
	}
	if !strings.Contains(out, "http://203.0.113.10 {") {
		t.Fatalf("站点地址应为 http://，实际:\n%s", out)
	}
	if strings.Contains(out, "Strict-Transport-Security") {
		t.Fatal("HTTP 模式不得发送 HSTS")
	}
}
