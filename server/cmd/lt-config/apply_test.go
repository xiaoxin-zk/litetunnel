package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// TestEnvFileSetKeepsComments 是最重要的一条：.env 是运维手工维护的文件，
// 里面全是注释与分组，重写一遍等于把排查线索全部抹掉。
func TestEnvFileSetKeepsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# 顶部说明\nLT_USER_PUBLIC_URL=https://old.example.com\n\n# 域名段\nLT_TUNNEL_DOMAIN=\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	env, vars, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if vars["LT_USER_PUBLIC_URL"] != "https://old.example.com" {
		t.Fatalf("解析结果不对: %v", vars)
	}

	if !env.set("LT_TUNNEL_DOMAIN", "tunnel.example.com") {
		t.Fatal("值变化时应返回 true")
	}
	if !env.set("LT_HTTPS_TUNNEL_MODE", "e2e") {
		t.Fatal("新键应被追加")
	}
	if err := env.write(true); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"# 顶部说明", "# 域名段", "LT_TUNNEL_DOMAIN=tunnel.example.com", "LT_HTTPS_TUNNEL_MODE=e2e"} {
		if !strings.Contains(got, want) {
			t.Errorf("写入结果缺少 %q:\n%s", want, got)
		}
	}

	// 含密钥时权限必须收紧：这个文件里有 DNS 凭据与 JWT 密钥。
	//
	// Windows 上跳过：那里的 Chmod 只支持只读位，Stat 一律报 0666，
	// 断言它只会得到一个与实现无关的失败。
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("含密钥时权限应为 0600，实际 %v", info.Mode().Perm())
		}
	}
}

// TestDeriveVars 覆盖派生规则：站点地址来自面板对外地址，
// 凭据默认走环境变量，端到端模式才产出公网入口端口。
func TestDeriveVars(t *testing.T) {
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	vars[tlscfg.VarHTTPSMode] = tlscfg.HTTPSModeE2E
	deriveVars(vars)

	if vars[tlscfg.VarPanelDomain] != "panel.example.com" {
		t.Errorf("站点地址应去掉 scheme，得到 %q", vars[tlscfg.VarPanelDomain])
	}
	if vars[tlscfg.VarACMEEmail] != "admin@panel.example.com" {
		t.Errorf("邮箱应回落到 admin@域名，得到 %q", vars[tlscfg.VarACMEEmail])
	}
	if vars[tlscfg.VarDNSArgs] != "{env."+tlscfg.VarDNSCredential+"}" {
		t.Errorf("凭据应默认从环境变量读，得到 %q", vars[tlscfg.VarDNSArgs])
	}
	if vars[tlscfg.VarHTTPSE2EPort] != "8444" {
		t.Errorf("端到端模式应产出公网入口端口，得到 %q", vars[tlscfg.VarHTTPSE2EPort])
	}

	// 切回边缘模式后，那个派生端口必须消失，否则模板会继续渲染
	// 「请放行 8444」的提示，而实际上该端口并不需要对外。
	vars[tlscfg.VarHTTPSMode] = tlscfg.HTTPSModeEdge
	deriveVars(vars)
	if _, ok := vars[tlscfg.VarHTTPSE2EPort]; ok {
		t.Error("边缘模式下不该有端到端入口端口")
	}
}
