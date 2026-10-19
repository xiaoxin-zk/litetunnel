package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

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

	if changed, err := env.set("LT_TUNNEL_DOMAIN", "tunnel.example.com"); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Fatal("值变化时应返回 true")
	}
	if changed, err := env.set("LT_HTTPS_TUNNEL_MODE", "e2e"); err != nil {
		t.Fatal(err)
	} else if !changed {
		t.Fatal("新键应被追加")
	}
	if err := env.write(); err != nil {
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

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("权限应为 0600，实际 %v", info.Mode().Perm())
		}
	}
}

func TestEnvFileSetRejectsLineBreaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("LT_CADDY_IMAGE=ghcr.io/ok/caddy:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env, _, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"token\nLT_CADDY_IMAGE=evil:latest",
		"token\rLT_CADDY_IMAGE=evil:latest",
		"token\r\nLT_CADDY_IMAGE=evil:latest",
		"token\x00suffix",
	} {
		if _, err := env.set(tlscfg.VarDNSCredential, bad); err == nil {
			t.Fatalf("含控制字符的值必须被拒绝，实际接受了 %q", bad)
		}
	}

	if err := env.write(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "evil") {
		t.Fatalf(".env 被注入了额外的配置行:\n%s", raw)
	}
}

func TestRenderAndApplyRejectsControlCharsInVars(t *testing.T) {
	s, p := newRenderOnlyService(t)

	_, err := s.renderAndApply(context.Background(), tlscfg.RenderRequest{
		Vars: map[string]string{
			tlscfg.VarUserPublicURL: "https://panel.example.com",
			tlscfg.VarDNSProvider:   "cloudflare",
			tlscfg.VarDNSCredential: "token\nLT_CADDY_IMAGE=evil:latest",
		},
		WriteEnv: true,
		Apply:    false,
	})
	if err == nil {
		t.Fatal("带换行的变量值必须被拒绝")
	}
	if !strings.Contains(err.Error(), "控制字符") {
		t.Fatalf("错误信息应指明原因，实际 %v", err)
	}
	if raw, rerr := os.ReadFile(p.envFile); rerr == nil && strings.Contains(string(raw), "evil") {
		t.Fatalf(".env 被写入了注入内容:\n%s", raw)
	}
}

func TestRenderAndApplyRejectsCaddyImageMismatch(t *testing.T) {
	s, _ := newRenderOnlyService(t)
	s.caddyImage = "caddy:2-alpine"

	_, err := s.renderAndApply(context.Background(), tlscfg.RenderRequest{
		Vars: map[string]string{
			tlscfg.VarUserPublicURL: "https://panel.example.com",
			tlscfg.VarDNSProvider:   "cloudflare",
		},
	})
	if err == nil {
		t.Fatal("校验镜像与 Compose 实际镜像不一致时必须报错")
	}
	if !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("错误信息应说明镜像不一致，实际 %v", err)
	}
}

func TestPrepareWritesFixesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上 Chmod 只支持只读位，权限断言没有意义")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "frps.toml")
	content := "auth.token = \"secret\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	batch, err := prepareWrites([]pendingWrite{
		{name: "frps.toml", path: path, content: content, mode: modeSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer batch.discard()

	if len(batch.changed) != 0 {
		t.Errorf("内容没变时不该报「文件已变化」，得到 %v", batch.changed)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("准备阶段不应修改权限，实际 %v", info.Mode().Perm())
	}

	if err := batch.commit(); err != nil {
		t.Fatal(err)
	}
	if len(batch.warn) == 0 {
		t.Error("权限被收紧应当留下提示，否则管理员不会知道磁盘上曾经是 0644")
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("权限应被收紧到 0600，实际 %v", info.Mode().Perm())
	}
}

func TestPrepareWritesLeavesDiskUntouchedOnFailure(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(good, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	batch, err := prepareWrites([]pendingWrite{
		{name: "Caddyfile", path: good, content: "new\n", mode: modeConfig},
		{name: "frps.toml", path: filepath.Join(dir, "missing", "frps.toml"), content: "new\n", mode: modeSecret},
	})
	if err == nil {
		batch.discard()
		t.Fatal("候选文件准备失败时应当报错")
	}

	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "old\n" {
		t.Errorf("准备阶段失败时不该动磁盘，实际内容 %q", raw)
	}
	if leftovers := tempLeftovers(t, dir); len(leftovers) > 0 {
		t.Errorf("准备失败后残留临时文件: %v", leftovers)
	}
}

func TestWriteBatchCommitRollsBackOnPartialFailure(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "Caddyfile")
	second := filepath.Join(dir, "frps.toml")
	if err := os.WriteFile(first, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("old-second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bakDir := second + ".lt-config-bak"
	if err := os.Mkdir(bakDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bakDir, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	batch, err := prepareWrites([]pendingWrite{
		{name: "Caddyfile", path: first, content: "new\n", mode: modeConfig},
		{name: "frps.toml", path: second, content: "new\n", mode: modeSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = batch.commit()
	if err == nil {
		t.Fatal("替换失败时应当报错")
	}
	if !strings.Contains(err.Error(), "已回滚") {
		t.Errorf("错误里应说明已回滚，实际 %q", err.Error())
	}
	if raw, rerr := os.ReadFile(first); rerr != nil || string(raw) != "old\n" {
		t.Errorf("排在前面的文件应当被回滚回旧内容，实际 %q / %v", raw, rerr)
	}
	if raw, rerr := os.ReadFile(second); rerr != nil || string(raw) != "old-second\n" {
		t.Errorf("未替换成功的文件应保持旧内容，实际 %q / %v", raw, rerr)
	}
	if leftovers := tempLeftovers(t, dir); len(leftovers) > 0 {
		t.Errorf("替换失败后残留临时文件: %v", leftovers)
	}
}

func TestRecoverBatchRollsBackWholeBatch(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "Caddyfile")
	second := filepath.Join(dir, "frps.toml")

	if err := os.WriteFile(first, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first+backupSuffix, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("old-second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"version":1,"dir":"` + strings.ReplaceAll(dir, `\`, `\\`) + `","files":[` +
		`{"name":"Caddyfile","path":"` + strings.ReplaceAll(first, `\`, `\\`) + `","tmp":"` +
		strings.ReplaceAll(filepath.Join(dir, ".lt-config-tmp-a"), `\`, `\\`) + `","existed":true},` +
		`{"name":"frps.toml","path":"` + strings.ReplaceAll(second, `\`, `\\`) + `","tmp":"` +
		strings.ReplaceAll(filepath.Join(dir, ".lt-config-tmp-b"), `\`, `\\`) + `","existed":true}]}`
	if err := os.WriteFile(filepath.Join(dir, batchManifestName), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupLeftovers(paths{
		deployDir: dir,
		caddyOut:  first,
		frpsOut:   second,
		envFile:   filepath.Join(dir, ".env"),
	})

	if raw, err := os.ReadFile(first); err != nil || string(raw) != "old\n" {
		t.Errorf("已替换的文件应回滚回旧内容，实际 %q / %v", raw, err)
	}
	if raw, err := os.ReadFile(second); err != nil || string(raw) != "old-second\n" {
		t.Errorf("未触碰的文件应保持原样，实际 %q / %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(dir, batchManifestName)); !os.IsNotExist(err) {
		t.Error("恢复完成后批次记录应被删除")
	}
	if _, err := os.Stat(first + backupSuffix); !os.IsNotExist(err) {
		t.Error("备份应已归位，不能留在部署目录里")
	}
	if leftovers := tempLeftovers(t, dir); len(leftovers) > 0 {
		t.Errorf("批次恢复后残留临时文件: %v", leftovers)
	}
}

func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".lt-config-tmp-") {
			out = append(out, e.Name())
		}
	}
	return out
}

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
	if vars[tlscfg.VarPanelScheme] != "https" || vars[tlscfg.VarHSTSOn] == "" {
		t.Errorf("HTTPS 地址应派生 https 站点并开启 HSTS，得到 scheme=%q hsts=%q",
			vars[tlscfg.VarPanelScheme], vars[tlscfg.VarHSTSOn])
	}

	vars[tlscfg.VarUserPublicURL] = "http://203.0.113.10"
	deriveVars(vars)
	if vars[tlscfg.VarPanelScheme] != "http" {
		t.Errorf("HTTP 地址应派生 http 站点，得到 %q", vars[tlscfg.VarPanelScheme])
	}
	if vars[tlscfg.VarHSTSOn] != "" {
		t.Errorf("HTTP 站点不能开启 HSTS，得到 %q", vars[tlscfg.VarHSTSOn])
	}
	if vars[tlscfg.VarPanelDomain] != "203.0.113.10" {
		t.Errorf("站点地址应保留 IP，得到 %q", vars[tlscfg.VarPanelDomain])
	}

	vars[tlscfg.VarHTTPSMode] = tlscfg.HTTPSModeEdge
	deriveVars(vars)
	if _, ok := vars[tlscfg.VarHTTPSE2EPort]; ok {
		t.Error("边缘模式下不该有端到端入口端口")
	}
}
