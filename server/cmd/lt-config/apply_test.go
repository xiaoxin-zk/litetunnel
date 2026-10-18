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

// TestEnvFileSetRejectsLineBreaks 覆盖「靠换行往 .env 追加变量」。
//
// .env 是逐行 key=value，值是直接拼在 '=' 后面的。于是 DNS 凭据里混进一个
// 换行，就等于往 .env 追加一整行——比如 LT_CADDY_IMAGE。而 compose 的
// image: ${LT_CADDY_IMAGE:-caddy:2-alpine} 接受任何来自 .env 的键，
// helper 却又用旧镜像校验过：校验的和实际重建的不是同一个镜像。
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

// TestRenderAndApplyRejectsControlCharsInVars 覆盖 helper 侧的第二道校验：
// 即使面板漏了检查，也不该把带换行的值写进 .env。
//
// helper 是独立的信任边界——它能写部署目录、能重建容器，因此不能假定
// 调用方一定做过校验。
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

// TestRenderAndApplyRejectsCaddyImageMismatch 覆盖「校验的镜像不是要上线的镜像」。
//
// LT_CFG_CADDY_IMAGE 是给运维用的校验镜像覆盖。一旦它与 .env 的
// LT_CADDY_IMAGE（compose 插值实际取的那个）不同，这次「校验通过」就只对
// 另一个镜像成立：官方镜像没有 dns 插件、自建镜像有，结果毫无参考价值。
func TestRenderAndApplyRejectsCaddyImageMismatch(t *testing.T) {
	s, _ := newRenderOnlyService(t)
	// .env 里是 ghcr.io/example/caddy-dns:latest，这里故意换一个。
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

// TestWriteBatchCommitRollsBackOnPartialFailure 覆盖替换阶段中途失败：必须整体
// 回滚到旧配置，且不留临时文件。
//
// 三个文件互相引用（Caddyfile 的域名要与 frps.toml 的 subDomainHost 一致，
// .env 的凭据要被 Caddyfile 的 {env.X} 取到），逐个替换到一半失败时若只报错
// 不回滚，磁盘上就是新旧混合的配置，要到下次容器重建才以错误形式爆炸。
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
	// 让第二个文件的「备份旧文件」这一步失败：预先放一个同名非空目录占据
	// 备份路径。于是 second 在 commit 的备份阶段就报错（磁盘上 second 仍是旧
	// 内容），而已经成功替换的 first 必须被回滚回旧内容。
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
	if vars[tlscfg.VarPanelScheme] != "https" || vars[tlscfg.VarHSTSOn] == "" {
		t.Errorf("HTTPS 地址应派生 https 站点并开启 HSTS，得到 scheme=%q hsts=%q",
			vars[tlscfg.VarPanelScheme], vars[tlscfg.VarHSTSOn])
	}

	// 无证书部署：协议与 HSTS 都必须跟着对外地址走，否则浏览器会被
	// HSTS 强制升级到一个根本没有证书的 https 站点。
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

	// 切回边缘模式后，那个派生端口必须消失，否则模板会继续渲染
	// 「请放行 8444」的提示，而实际上该端口并不需要对外。
	vars[tlscfg.VarHTTPSMode] = tlscfg.HTTPSModeEdge
	deriveVars(vars)
	if _, ok := vars[tlscfg.VarHTTPSE2EPort]; ok {
		t.Error("边缘模式下不该有端到端入口端口")
	}
}
