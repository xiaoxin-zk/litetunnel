package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 这一组守的是「保存并校验」的语义：只校验，不写盘。
//
// 背景：Caddyfile、frps.toml 与 .env 都是**容器直接挂载**的活动配置
// （deploy/docker-compose.yml 挂给 caddy 与 frps，restart 策略是
// unless-stopped）。校验阶段把它们改掉，之后宿主机或容器只要重启一次，
// 这份「还没应用」的新配置就会真的生效——而面板侧记录的状态仍是上一份，
// 两边对不上，也没有任何地方会提示。
//
// 断言很直白：Apply=false 时，磁盘上的三个文件一个字节都没变。

const testEnvContent = `# 部署配置
LT_USER_PUBLIC_URL=https://panel.example.com
LT_USER_PORT=7848
LT_GATEWAY_PORT=7001
LT_KCP_PORT=7000
LT_VHOST_HTTP_PORT=80
LT_VHOST_HTTPS_PORT=443
LT_FRPS_TOKEN=token-value
LT_PORT_RANGE_START=20000
LT_PORT_RANGE_END=30000
LT_MAX_PORTS_PER_USER=10
LT_FRPS_API_PORT=7500
LT_FRPS_API_USER=admin
LT_FRPS_API_PASSWORD=pass-value
LT_CADDY_IMAGE=ghcr.io/example/caddy-dns:latest
LT_CADDY_DNS_PROVIDER=cloudflare
LT_CADDY_DNS_CREDENTIAL=old-credential
`

// newRenderOnlyService 造一个只差 docker 的 service：模板与部署目录都用临时目录，
// 容器校验换成必定通过的替身。
func newRenderOnlyService(t *testing.T) (*service, paths) {
	t.Helper()
	dir := t.TempDir()

	p := paths{
		deployDir: dir,
		envFile:   filepath.Join(dir, ".env"),
		caddyTpl:  filepath.Join(dir, "Caddyfile.template"),
		caddyOut:  filepath.Join(dir, "Caddyfile"),
		frpsTpl:   filepath.Join(dir, "frps.toml.template"),
		frpsOut:   filepath.Join(dir, "frps.toml"),
	}

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("写入 %s 失败: %v", path, err)
		}
	}
	write(p.envFile, testEnvContent)
	// 活动文件先放上哨兵内容：任何写入都会被发现。
	write(p.caddyOut, "OLD-CADDYFILE\n")
	write(p.frpsOut, "OLD-FRPS\n")
	// 模板用最简内容：本用例关心的是「写不写盘」，不是渲染结果。
	write(p.caddyTpl, "rendered-caddy\n")
	write(p.frpsTpl, "rendered-frps\n")

	s := &service{paths: p, allowApply: false}
	s.validateFn = func(_, _, _ string, _ map[string]string) (string, error) {
		return "校验替身：通过", nil
	}
	return s, p
}

func TestRenderOnlyDoesNotTouchActiveFiles(t *testing.T) {
	s, p := newRenderOnlyService(t)

	res, err := s.renderAndApply(tlscfg.RenderRequest{
		Vars: map[string]string{
			tlscfg.VarUserPublicURL: "https://panel.example.com",
			tlscfg.VarTunnelDomain:  "tunnel.example.com",
			tlscfg.VarDNSProvider:   "cloudflare",
			// 凭据变了。若这里写了盘，被容器挂载的活动 .env 就已经被改掉了，
			// 下一次容器重启会拿着这份「还没应用」的配置起来。
			tlscfg.VarDNSCredential: "new-credential",
		},
		WriteEnv: true,
		Apply:    false,
	})
	if err != nil {
		t.Fatalf("校验模式不该失败: %v", err)
	}

	raw, err := os.ReadFile(p.envFile)
	if err != nil {
		t.Fatalf("读 .env 失败: %v", err)
	}
	if strings.Contains(string(raw), "new-credential") {
		t.Fatal("只校验不应用时活动 .env 被改写了：它直接挂载给容器，重启后未应用的配置就会生效")
	}
	if !strings.Contains(string(raw), "old-credential") {
		t.Fatalf(".env 应当原样保留，实际内容:\n%s", raw)
	}

	for name, path := range map[string]string{"Caddyfile": p.caddyOut, "frps.toml": p.frpsOut} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读 %s 失败: %v", name, err)
		}
		if !strings.HasPrefix(string(got), "OLD-") {
			t.Fatalf("%s 被改写了（实际 %q）：校验阶段不该碰活动配置文件", name, got)
		}
	}

	if res.Applied {
		t.Fatal("只校验的请求不该报告为已应用")
	}

	// 但同时要告诉管理员「点了应用会改哪些文件」，否则这个按钮等于没有反馈。
	want := map[string]bool{"Caddyfile": true, "frps.toml": true, ".env": true}
	for _, name := range res.Changed {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("应当报告将要变化的文件，缺少 %v（实际 %v）", want, res.Changed)
	}
}

// TestRenderOnlyReportsNoChangeWhenIdentical 覆盖「内容本来就一致」：此时不该
// 报告任何变化，也不该写盘。
func TestRenderOnlyReportsNoChangeWhenIdentical(t *testing.T) {
	s, p := newRenderOnlyService(t)

	// 让两个配置文件的磁盘内容与渲染结果一致，模拟「什么都没改就点了校验」。
	// .env 不参与：它的文本由 envfile 重新排版，手写的样例必然有格式差异，
	// 那是另一个话题（写回时的规范化），与「写不写盘」无关。
	if err := os.WriteFile(p.caddyOut, []byte("rendered-caddy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.frpsOut, []byte("rendered-frps\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := s.renderAndApply(tlscfg.RenderRequest{
		Vars: map[string]string{
			tlscfg.VarUserPublicURL: "https://panel.example.com",
			tlscfg.VarTunnelDomain:  "tunnel.example.com",
			tlscfg.VarDNSProvider:   "cloudflare",
			tlscfg.VarDNSCredential: "old-credential",
		},
		WriteEnv: false,
		Apply:    false,
	})
	if err != nil {
		t.Fatalf("校验模式不该失败: %v", err)
	}
	if len(res.Changed) != 0 {
		t.Fatalf("内容一致时不该报告变化，实际 %v", res.Changed)
	}
}
