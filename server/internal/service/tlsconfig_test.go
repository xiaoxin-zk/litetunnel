package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// TestHTTPSProxyEntryAndAddr 覆盖「HTTPS 隧道到底有没有公网入口」。
//
// 这条判定同时决定三件事，三者必须一致，否则用户会拿到互相矛盾的结论：
//
//   - 没有入口时创建 HTTPS 隧道要被拒绝（而不是建出一条永远打不开的）；
//   - 没有入口时不能给出 443 的假地址（浏览器会报证书不匹配）；
//   - 有入口时地址必须带上那个端口（端到端模式下 443 是 Caddy 的地盘）。
func TestHTTPSProxyEntryAndAddr(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:   "tunnel.example.com",
		GatewayHost:    "203.0.113.10",
		VhostHTTPSPort: 8444,
	})
	g := &model.Group{AllowProtocols: "tcp,udp,http,https"}
	u := &model.User{ID: 1, Username: "entryuser"}
	httpsInput := TunnelInput{Name: "web", Type: model.ProxyTypeHTTPS, LocalPort: 8080, Subdomain: "web"}

	// .env 里没写模式时按 edge 处理：没有 HTTPS 隧道的公网入口。
	if svc.DomainHTTPSMode() != tlscfg.HTTPSModeEdge {
		t.Fatalf("默认模式应为 edge，实际 %s", svc.DomainHTTPSMode())
	}
	if svc.HTTPSProxyEntryEnabled() || svc.HTTPSProxyEntry() != "" {
		t.Fatal("边缘模式下不该认为存在 HTTPS 隧道入口")
	}
	if _, err := svc.normalizeInput(u, g, httpsInput); !errors.Is(err, ErrNoHTTPSProxyEntry) {
		t.Fatalf("边缘模式下创建 HTTPS 隧道应当被拒绝，实际 %v", err)
	}
	httpsTunnel := &model.Tunnel{Type: model.ProxyTypeHTTPS, Subdomain: "web"}
	if got := svc.TunnelPublicAddr(httpsTunnel); got != "" {
		t.Fatalf("没有入口时不该给出地址（会让人以为隧道是通的），得到 %q", got)
	}

	// 切到端到端模式：入口出现，且地址必须带端口。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainHTTPSMode: tlscfg.HTTPSModeE2E}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	if !svc.HTTPSProxyEntryEnabled() {
		t.Fatal("端到端模式下应当存在 HTTPS 隧道入口")
	}
	if got := svc.HTTPSProxyEntry(); got != "203.0.113.10:8444" {
		t.Fatalf("入口应为 203.0.113.10:8444，实际 %q", got)
	}
	if got := svc.TunnelPublicAddr(httpsTunnel); got != "https://web.tunnel.example.com:8444" {
		t.Fatalf("HTTPS 隧道的地址应带上入口端口，实际 %q", got)
	}
	if _, err := svc.normalizeInput(u, g, httpsInput); err != nil {
		t.Fatalf("端到端模式下应当允许创建 HTTPS 隧道: %v", err)
	}

	// HTTP 隧道始终走 Caddy 的 443：不受模式影响，也不带端口。
	httpTunnel := &model.Tunnel{Type: model.ProxyTypeHTTP, Subdomain: "web"}
	if got := svc.TunnelPublicAddr(httpTunnel); got != "https://web.tunnel.example.com" {
		t.Fatalf("HTTP 隧道的地址不该带端口，实际 %q", got)
	}
	// TCP 隧道走网关地址 + 分配到的端口。
	tcpTunnel := &model.Tunnel{Type: model.ProxyTypeTCP, RemotePort: 23456}
	if got := svc.TunnelPublicAddr(tcpTunnel); got != "203.0.113.10:23456" {
		t.Fatalf("TCP 隧道地址不对，实际 %q", got)
	}
}

// TestTunnelDomainPrefersSetting 覆盖「管理端改了域名、面板仍按旧域名判权」。
//
// 面板容器不会因为改域名而重启，Cfg 里还是启动时的旧值；而 Caddy 与 frps
// 已经按新域名重建了。此时若继续照 Cfg 取值，就会出现
// 「新域名的子域被拒绝、旧域名的子域被放行」——放行的那条隧道在 Caddy 上
// 根本没有对应配置，用户只会看到连不上。
func TestTunnelDomainPrefersSetting(t *testing.T) {
	svc := newTestServices(t, &config.Config{TunnelDomain: "old.example.com"})

	if got := svc.TunnelDomain(); got != "old.example.com" {
		t.Fatalf("未改设置时应回落到环境变量，实际 %q", got)
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainTunnel: "new.example.com"}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	if got := svc.TunnelDomain(); got != "new.example.com" {
		t.Fatalf("设置优先，实际 %q", got)
	}

	// 自定义域名只能落在当前生效的域名之下。
	g := &model.Group{AllowProtocols: "http", AllowCustomDomain: true}
	u := &model.User{ID: 1, Username: "duser"}
	if _, err := svc.normalizeInput(u, g, TunnelInput{
		Name: "site", Type: model.ProxyTypeHTTP, LocalPort: 8080, Domain: "a.new.example.com",
	}); err != nil {
		t.Fatalf("新域名之下的自定义域名应当允许: %v", err)
	}
	if _, err := svc.normalizeInput(u, g, TunnelInput{
		Name: "site2", Type: model.ProxyTypeHTTP, LocalPort: 8080, Domain: "a.old.example.com",
	}); !errors.Is(err, ErrDomainDenied) {
		t.Fatalf("旧域名之下的自定义域名应当拒绝，实际 %v", err)
	}
}

// TestTunnelWriteErrorClassification 覆盖「隧道名冲突被当成端口撞车」。
//
// 误判的代价不只是多试 5 次：日志里会出现 5 行「端口分配撞车」，
// 把排查方向直接带偏；而且最终抛给用户的是数据库原文，
// 界面只会显示一句「服务内部错误」。
func TestTunnelWriteErrorClassification(t *testing.T) {
	cases := []struct {
		err        error
		port, name bool
	}{
		{nil, false, false},
		{errors.New("UNIQUE constraint failed: lt_tunnels.remote_port"), true, false},
		{errors.New(`ERROR: duplicate key value violates unique constraint "idx_lt_tunnels_remote_port"`), true, false},
		{errors.New("UNIQUE constraint failed: lt_tunnels.user_id, lt_tunnels.name"), false, true},
		{errors.New(`ERROR: duplicate key value violates unique constraint "idx_user_tunnel"`), false, true},
		{errors.New("connection refused"), false, false},
		{errors.New("context deadline exceeded"), false, false},
	}
	for _, tc := range cases {
		if got := isPortConflict(tc.err); got != tc.port {
			t.Errorf("isPortConflict(%v) = %v，期望 %v", tc.err, got, tc.port)
		}
		if got := isNameConflict(tc.err); got != tc.name {
			t.Errorf("isNameConflict(%v) = %v，期望 %v", tc.err, got, tc.name)
		}
	}

	nameErr := describeTunnelWriteError(errors.New("UNIQUE constraint failed: lt_tunnels.user_id, lt_tunnels.name"))
	if !errors.Is(nameErr, ErrInvalidParam) {
		t.Fatalf("名称冲突应翻译成参数错误，实际 %v", nameErr)
	}
	if !strings.Contains(nameErr.Error(), "隧道名") {
		t.Fatalf("提示里应说明是隧道名的问题，实际 %v", nameErr)
	}

	// 端口冲突原样返回：要不要重试由调用方决定。
	raw := errors.New("UNIQUE constraint failed: lt_tunnels.remote_port")
	if got := describeTunnelWriteError(raw); got != raw {
		t.Fatalf("端口冲突不该被改写，得到 %v", got)
	}
}
