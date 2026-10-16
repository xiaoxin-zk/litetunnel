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

	// .env 的权限必须**无条件**是 0600：这个文件里有 DNS 凭据、JWT 密钥
	// 与数据库口令，而权限不该取决于本次请求带了哪些字段。
	//
	// Windows 上跳过：那里的 Chmod 只支持只读位，Stat 一律报 0666，
	// 断言它只会得到一个与实现无关的失败。
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

// TestPrepareWritesFixesLoosePermissions 覆盖「内容没变就不重写」带来的副作用：
// 早期版本给 frps.toml 与 .env 写过 0644，只比较内容就跳过的话，那份宽松权限
// 会永远留在磁盘上。这里断言它会被纠正，且不会因此把文件内容重写一遍。
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
	// 绕过 umask 与平台默认值，确保起点确实是 0644。
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
	if len(batch.warn) == 0 {
		t.Error("权限被收紧应当留下提示，否则管理员不会知道磁盘上曾经是 0644")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("权限应被收紧到 0600，实际 %v", info.Mode().Perm())
	}
}

// TestPrepareWritesLeavesDiskUntouchedOnFailure 覆盖多文件更新最要紧的一点：
// 只要有一个候选文件准备不出来，已经准备好的那些也不能落盘。
// 逐个写盘的实现会在这里留下半新半旧的配置——Caddyfile 已是新域名，
// frps.toml 还是旧的，两边对不上。
func TestPrepareWritesLeavesDiskUntouchedOnFailure(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(good, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	batch, err := prepareWrites([]pendingWrite{
		{name: "Caddyfile", path: good, content: "new\n", mode: modeConfig},
		// 父目录不存在：这个候选一定准备不出来。
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

// TestWriteBatchCommitReportsPartialState 覆盖替换阶段中途失败：不回滚，
// 但必须说清边界（已经替换了几个文件），且不留临时文件。
func TestWriteBatchCommitReportsPartialState(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "Caddyfile")
	second := filepath.Join(dir, "frps.toml")
	if err := os.WriteFile(first, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 目标路径是个非空目录：把文件 rename 上去必然失败。
	if err := os.Mkdir(second, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "keep"), []byte("x"), 0o600); err != nil {
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
	if !strings.Contains(err.Error(), "已替换 1 个文件") {
		t.Errorf("错误里应说明已经替换了几个文件，实际 %q", err.Error())
	}
	if raw, rerr := os.ReadFile(first); rerr != nil || string(raw) != "new\n" {
		t.Errorf("排在前面的文件应当已经替换，实际 %q / %v", raw, rerr)
	}
	if leftovers := tempLeftovers(t, dir); len(leftovers) > 0 {
		t.Errorf("替换失败后残留临时文件: %v", leftovers)
	}
}

// tempLeftovers 列出目录里残留的临时文件。
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
