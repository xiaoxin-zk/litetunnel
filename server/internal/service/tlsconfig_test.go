package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
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
		UserPublicURL:  "https://panel.example.com",
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

	// 保存期望值：运行期行为**不能**跟着变。Caddy 与 frps 还是上一份配置，
	// 这时放行 HTTPS 隧道只会得到一条永远打不开的隧道。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainHTTPSMode: tlscfg.HTTPSModeE2E}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	if svc.HTTPSProxyEntryEnabled() {
		t.Fatal("只保存、还没下发时不该认为 HTTPS 隧道已经有入口")
	}
	if !svc.DomainPending() {
		t.Fatal("保存之后应当处于「待下发」状态，界面要据此提示")
	}

	// 下发成功（helper 渲染、校验并重建了容器）之后才切换运行期行为。
	applyDomain(t, svc)
	if !svc.HTTPSProxyEntryEnabled() {
		t.Fatal("端到端模式下应当存在 HTTPS 隧道入口")
	}
	if svc.DomainPending() {
		t.Fatal("下发成功后不该仍是「待下发」")
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

// applyDomain 模拟一次成功的下发：组装变量 + 记录「已生效」。
//
// 面板与宿主机之间那一步（调 helper、重建容器）不在这些用例的覆盖范围内，
// 关心的只是「什么时候算生效」。
func applyDomain(t *testing.T, svc *Services) {
	t.Helper()
	vars, err := svc.DomainConfigVars()
	if err != nil {
		t.Fatalf("组装下发变量失败: %v", err)
	}
	if err := svc.markDomainApplied(vars); err != nil {
		t.Fatalf("记录已生效的配置失败: %v", err)
	}
}

// TestTunnelDomainFollowsApplied 覆盖「管理端改了域名，面板该按哪个域名判权」。
//
//	Cfg 里是**面板启动时**的旧值（改域名不会重启面板容器）；
//	设置里是管理员刚保存的**期望值**（可能还没下发）；
//	只有「已生效」的那一份与 Caddy / frps 上的实际配置一致。
//
// 取错任何一个都会得到同一类故障：放行的域名在 Caddy 上没有对应路由，
// 用户只看到连不上，而界面上一切正常。
func TestTunnelDomainFollowsApplied(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "old.example.com",
		UserPublicURL: "https://panel.example.com",
	})

	if got := svc.TunnelDomain(); got != "old.example.com" {
		t.Fatalf("没有任何下发记录时应回落到环境变量，实际 %q", got)
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainTunnel: "new.example.com"}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	// 只保存：仍按旧域名判权。放行新域名的子域等于放行一条不存在的路由。
	if got := svc.TunnelDomain(); got != "old.example.com" {
		t.Fatalf("只保存未下发时应继续按已生效的域名，实际 %q", got)
	}

	g := &model.Group{AllowProtocols: "http", AllowCustomDomain: true}
	u := &model.User{ID: 1, Username: "duser"}
	if _, err := svc.normalizeInput(u, g, TunnelInput{
		Name: "site", Type: model.ProxyTypeHTTP, LocalPort: 8080, Domain: "a.new.example.com",
	}); !errors.Is(err, ErrDomainDenied) {
		t.Fatalf("新域名还没生效时不该放行它的子域，实际 %v", err)
	}

	applyDomain(t, svc)
	if got := svc.TunnelDomain(); got != "new.example.com" {
		t.Fatalf("下发后应按新域名判权，实际 %q", got)
	}
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

// TestDomainPendingFalseWhenOnlyEnvConfigured 覆盖「手工部署、没进过后台」这一档。
//
// 这类部署只用 .env 配域名，设置表里没有 domain.panel / domain.tunnel 的记录，
// 也没有任何一次下发。此时运行期本就按 .env 在跑，界面必须显示「与期望一致」；
// 若 Applied 不回落到 .env，就会得到「空 vs .env」的假差异，页面永久提示
// 「已保存的配置还没有在宿主机上生效」，把管理员引去点一次根本不需要的下发。
func TestDomainPendingFalseWhenOnlyEnvConfigured(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:   "tunnel.example.com",
		UserPublicURL:  "https://panel.example.com",
		HTTPSProxyMode: tlscfg.HTTPSModeE2E,
	})

	got := svc.DomainApplied()
	want := DomainAppliedSet{
		Panel:     "panel.example.com",
		Tunnel:    "tunnel.example.com",
		HTTPSMode: tlscfg.HTTPSModeE2E,
	}
	if got != want {
		t.Fatalf("没有下发记录时「已生效」应等于 .env 的实际配置，得到 %+v，期望 %+v", got, want)
	}
	if svc.DomainPending() {
		t.Fatal("只用 .env 配好、且从未进过后台的部署不该显示「待下发」")
	}

	// 只保存未下发：这时才该亮起「待下发」。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainPanel: "new.example.com"}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	if !svc.DomainPending() {
		t.Fatal("保存了新域名但还没下发时应当处于「待下发」状态")
	}
	if got := svc.DomainApplied().Panel; got != "panel.example.com" {
		t.Fatalf("只保存未下发时「已生效」仍应是 .env 的旧值，实际 %q", got)
	}
}

// TestBootstrapAppliedDomainAlignsUpgradePath 覆盖升级路径的一次性对齐。
//
// 「已生效」是后加的字段。升级前管理员若改过域名（期望值存了库），升级后
// 若没有基线，运行期会回落到面板启动时的环境变量——那是个更旧的域名，
// 子域名隧道会立刻失效。这里断言会把已有的期望值补成基线。
func TestBootstrapAppliedDomainAlignsUpgradePath(t *testing.T) {
	cfg := &config.Config{
		Env:          "test",
		LogLevel:     "warn",
		DBDriver:     "sqlite",
		DBDSN:        filepath.Join(t.TempDir(), "test.db"),
		APIKeyEncKey: "test-api-key-enc",
		TunnelDomain: "env.example.com",
	}
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	// 升级前的状态：管理员在页面上改过隧道根域名，但没有「已生效」记录。
	if err := db.Create(&model.Setting{
		Key: string(KeyDomainTunnel), Value: "panel-set.example.com",
	}).Error; err != nil {
		t.Fatalf("写入历史设置失败: %v", err)
	}

	s := NewSettingStore(db, cfg)
	if got := s.Get(KeyDomainAppliedTunnel); got != "panel-set.example.com" {
		t.Fatalf("升级后应把已有的期望值记为已生效，实际 %q", got)
	}
	// 从未用过的项不能被凭空补上：那种部署必须继续以 .env 为准。
	if got := s.Get(KeyDomainAppliedPanel); got != "" {
		t.Fatalf("没有期望值的项不该被补成已生效，实际 %q", got)
	}

	// 这一组由系统维护，管理端不能手工改，也不会出现在管理端返回里。
	if err := s.SetMany(map[SettingKey]string{KeyDomainAppliedTunnel: "evil.example.com"}); err == nil {
		t.Fatal("「已生效」这一组不该允许通过设置接口写入")
	}
	if _, ok := s.AllForAdmin()[string(KeyDomainAppliedTunnel)]; ok {
		t.Fatal("「已生效」这一组不该出现在管理端返回中")
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
