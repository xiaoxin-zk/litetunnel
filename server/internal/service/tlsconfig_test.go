package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestPanelPublicURLKeepsConfiguredScheme 覆盖「没有域名证书也能用 HTTP」。
//
// 协议只由部署配置（LT_USER_PUBLIC_URL）决定，界面里保存的仍是不带 scheme 的
// 域名：这样 Caddy 渲染、找回密码链接与客户端地址三处始终一致，不会出现
// 「Caddy 按 HTTP 起、邮件链接却写 https」的错配。
func TestPanelPublicURLKeepsConfiguredScheme(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want string
	}{
		{"http://panel.example.com", "http://panel.example.com"},
		{"https://panel.example.com", "https://panel.example.com"},
		{"http://panel.example.com/", "http://panel.example.com"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			svc := newTestServices(t, &config.Config{UserPublicURL: tc.env})
			if got := svc.UserPublicURL(); got != tc.want {
				t.Fatalf("UserPublicURL 应为 %q，实际 %q", tc.want, got)
			}
			vars, err := svc.DomainConfigVars()
			if err != nil {
				t.Fatalf("组装下发变量失败: %v", err)
			}
			if got := vars[tlscfg.VarUserPublicURL]; got != tc.want {
				t.Fatalf("下发给 helper 的地址应为 %q，实际 %q", tc.want, got)
			}
		})
	}
}

// TestAppliedPanelKeepsConfiguredScheme 覆盖「已下发」路径：
// 记录里存的是裸域名，协议必须从部署配置继承，而不是一律补 https。
func TestAppliedPanelKeepsConfiguredScheme(t *testing.T) {
	svc := newTestServices(t, &config.Config{UserPublicURL: "http://panel.example.com"})
	if err := svc.Settings.SetInternal(map[SettingKey]string{
		KeyDomainAppliedPanel: "panel.example.com",
	}); err != nil {
		t.Fatalf("写入已生效记录失败: %v", err)
	}
	if got := svc.UserPublicURL(); got != "http://panel.example.com" {
		t.Fatalf("已下发记录也必须保留 HTTP，实际 %q", got)
	}
}

// TestUpgradeDoesNotAssumeDesiredApplied 覆盖升级路径**不猜**的取舍。
//
// 老版本里运行期按库中的期望值算，所以存在一种诱惑：升级后把期望值直接记为
// 已生效，省掉管理员一次下发。但那份期望值有没有真的下发过（helper 是否成功
// 重建过 caddy 与 frps），面板无从得知——猜错就是让流量走在与界面不符的配置上。
// 因此这里断言什么都不补：已生效那一组保持为空，运行期以 .env 为准，
// 界面显示「待下发」，由管理员点一次下发来收敛。
func TestUpgradeDoesNotAssumeDesiredApplied(t *testing.T) {
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
	for _, k := range []SettingKey{KeyDomainAppliedPanel, KeyDomainAppliedTunnel, KeyDomainAppliedMode} {
		if got := s.Get(k); got != "" {
			t.Errorf("升级时不该把期望值当成已生效（%s = %q）", k, got)
		}
		if s.hasRow(k) {
			t.Errorf("升级时不该凭空造出「已生效」记录（%s）", k)
		}
	}
	// 期望值本身要留着：界面靠它显示「待下发」。
	if got := s.Get(KeyDomainTunnel); got != "panel-set.example.com" || !s.hasRow(KeyDomainTunnel) {
		t.Fatalf("期望值不该被动过，实际 %q", got)
	}

	// 于是运行期按 .env 判权，而界面如实提示「待下发」。
	svc := New(db, cfg)
	if got := svc.TunnelDomain(); got != "env.example.com" {
		t.Fatalf("没有下发记录时运行期必须以 .env 为准，实际 %q", got)
	}
	if !svc.DomainPending() {
		t.Fatal("库里的期望值与 .env 不一致时必须显示「待下发」，否则等于谎报已生效")
	}

	// 这一组由系统维护，管理端不能手工改，也不会出现在管理端返回里。
	if err := s.SetMany(map[SettingKey]string{KeyDomainAppliedTunnel: "evil.example.com"}); err == nil {
		t.Fatal("「已生效」这一组不该允许通过设置接口写入")
	}
	if _, ok := s.AllForAdmin()[string(KeyDomainAppliedTunnel)]; ok {
		t.Fatal("「已生效」这一组不该出现在管理端返回中")
	}
}

// TestEmptyTunnelDomainMeansDisabled 覆盖「空域名 = 明确关闭隧道」。
//
// 「留空即关闭」是界面上的承诺（Caddyfile 模板里整段泛域名站点块也会被剪掉），
// 但判据必须是「库里有没有这一行」，而不是「值是否为空」：否则清空保存会被
// 当成「从没配过」而回落到 .env，关闭动作成了空操作，用户看到「已关闭」而
// 泛域名隧道其实还开着。
func TestEmptyTunnelDomainMeansDisabled(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "tunnel.example.com",
		UserPublicURL: "https://panel.example.com",
	})

	// 从未配置过：以 .env 为准。
	if got := svc.DesiredTunnelDomain(); got != "tunnel.example.com" {
		t.Fatalf("没有行时应当以 .env 为准，实际 %q", got)
	}

	// 显式清空：走真实保存路径（含校验），期望值必须真的变成「关闭」。
	if err := svc.UpdateSettings(map[SettingKey]string{KeyDomainTunnel: ""}); err != nil {
		t.Fatalf("清空隧道根域名失败: %v", err)
	}
	if got := svc.DesiredTunnelDomain(); got != "" {
		t.Fatalf("清空后应当表达「关闭」，不该回落到 .env 得到 %q", got)
	}
	// 期望值变了、还没下发：运行期仍按 .env 的旧域名判权。
	if got := svc.TunnelDomain(); got != "tunnel.example.com" {
		t.Fatalf("只保存未下发时应继续按 .env 判权，实际 %q", got)
	}
	if !svc.DomainPending() {
		t.Fatal("「已关闭」还没下发时必须显示「待下发」")
	}

	// 下发之后隧道才算真的关掉：连二级域名都建不出来。
	applyDomain(t, svc)
	if got := svc.TunnelDomain(); got != "" {
		t.Fatalf("下发后隧道应当已关闭，实际 %q", got)
	}
	if svc.DomainPending() {
		t.Fatalf("关闭同样是一次成功的下发，不该仍显示「待下发」（desired=%+v applied=%+v）",
			svc.DomainDesired(), svc.DomainApplied())
	}

	g := &model.Group{AllowProtocols: "http"}
	u := &model.User{ID: 1, Username: "closeduser"}
	if _, err := svc.normalizeInput(u, g, TunnelInput{
		Name: "site", Type: model.ProxyTypeHTTP, LocalPort: 8080, Subdomain: "web",
	}); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("隧道关闭后不该再允许创建子域名隧道，实际 %v", err)
	}
}

// TestDomainPendingCoversCertificateSettings 覆盖「只保存证书参数时页面不报待下发」。
//
// DomainPending 曾经只比较面板域名 / 隧道域名 / HTTPS 模式。但 DNS 服务商、
// DNS 参数、凭据与 ACME 邮箱同样会改变渲染出的 Caddyfile 与 Caddy 的运行
// 配置：只保存它们、还没下发时，磁盘上跑的还是旧配置，而页面显示「与期望
// 一致」——这正是这一页存在的意义所在。
func TestDomainPendingCoversCertificateSettings(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "tunnel.example.com",
		UserPublicURL: "https://panel.example.com",
	})

	// 从未用过这个页面：期望值与 .env 同口径，不该报待下发。
	if svc.DomainPending() {
		t.Fatal("只用 .env 配好的部署不该显示「待下发」")
	}

	steps := []struct {
		name  string
		key   SettingKey
		value string
	}{
		{"ACME 邮箱", KeyDomainACMEEmail, "ops@example.com"},
		{"DNS 服务商", KeyDomainDNSProvider, "cloudflare"},
		{"DNS 参数", KeyDomainDNSArgs, "{env.LT_CADDY_DNS_CREDENTIAL}"},
		{"DNS 凭据", KeyDomainDNSCredential, "super-secret-token"},
	}
	for _, st := range steps {
		if err := svc.Settings.SetMany(map[SettingKey]string{st.key: st.value}); err != nil {
			t.Fatalf("写入 %s 失败: %v", st.name, err)
		}
		if !svc.DomainPending() {
			t.Fatalf("只保存了「%s」，页面必须显示「待下发」", st.name)
		}
		// 下发一次回到一致状态，让下一轮从干净状态开始。
		applyDomain(t, svc)
		if svc.DomainPending() {
			t.Fatalf("「%s」下发之后不该仍是「待下发」", st.name)
		}
	}

	// 摘要只记哈希：凭据明文不能被复制到设置表里。
	var row model.Setting
	if err := svc.DB.Where("key = ?", string(KeyDomainAppliedDigest)).First(&row).Error; err != nil {
		t.Fatalf("读取已应用摘要失败: %v", err)
	}
	if row.Value == "" {
		t.Fatal("下发之后必须记下摘要，否则下一轮比较恒为「待下发」")
	}
	if strings.Contains(row.Value, "super-secret-token") {
		t.Fatal("已应用摘要里不能出现凭据明文")
	}
}

// TestDomainPendingIgnoresUnrelatedSettings 是上一条的反面。
//
// 摘要必须只覆盖「下发输入」。把所有设置项都算进去的话，改个站点公告、
// SMTP 端口都会让「待下发」亮起来，管理员很快就会学会无视这个提示。
func TestDomainPendingIgnoresUnrelatedSettings(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "tunnel.example.com",
		UserPublicURL: "https://panel.example.com",
	})

	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeySMTPHost:         "smtp.example.com",
		KeySMTPPort:         "465",
		KeySiteAnnouncement: "维护通知",
		KeyRegisterEnabled:  "false",
	}); err != nil {
		t.Fatalf("写入无关配置失败: %v", err)
	}
	if svc.DomainPending() {
		t.Fatal("与下发无关的配置不该让「待下发」亮起来")
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

// TestApplyDomainConfigWaitsForDomainMu 覆盖「下发流程整段互斥」。
//
// 两次「保存并应用」交错时，可能后到的那次先完成：宿主机上跑的是旧配置，
// 「已生效」标记却写成了先到那份的，或反过来。竞态本身无法稳定复现
// （SQLite 单连接天然串行化数据库层），所以这里沿用 TestCreateTunnelWaitsForUserLock
// 的思路——直接验证「下发确实会先取 domainMu」这个结构前提。
func TestApplyDomainConfigWaitsForDomainMu(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.domainMu.Lock() // 模拟「另一次下发正在进行」
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = svc.ApplyDomainConfig(context.Background(), true) // helper 未配置，会快速返回错误
	}()

	select {
	case <-done:
		t.Fatal("另一个下发还没结束时，第二次下发不应当进入临界区")
	case <-time.After(50 * time.Millisecond):
		// 仍在等锁：符合预期。
	}

	svc.domainMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("锁释放后下发应当继续完成")
	}
}

// TestUpdateSettingsDomainSaveWaitsForApply 覆盖「保存与下发互斥」的范围：
// 改「域名与证书」的保存必须排在一次进行中的下发后面——下发是逐个 key
// 读设置，读到一半插进一次保存会把「从未保存过的组合」原样下发出去；
// 而改无关设置的保存不该被下发拖住。
func TestUpdateSettingsDomainSaveWaitsForApply(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.domainMu.Lock() // 模拟「下发正在进行」
	defer svc.domainMu.Unlock()

	// 无关设置的保存：不必等下发，立刻就能完成。
	doneOther := make(chan error, 1)
	go func() { doneOther <- svc.UpdateSettings(map[SettingKey]string{KeySiteAnnouncement: "维护通知"}) }()
	select {
	case err := <-doneOther:
		if err != nil {
			t.Fatalf("无关设置的保存不该被下发阻塞，也不该失败: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("与域名无关的保存被不必要地挡在了一次下发后面")
	}

	// 改「域名与证书」的保存：必须等下发结束。
	doneDomain := make(chan error, 1)
	go func() { doneDomain <- svc.UpdateSettings(map[SettingKey]string{KeyDomainACMEEmail: "ops@example.com"}) }()
	select {
	case <-doneDomain:
		t.Fatal("改域名组的保存不该在下发进行中完成")
	case <-time.After(50 * time.Millisecond):
		// 仍在等锁：符合预期。
	}
	// 不释放锁直接返回：doneDomain 里的协程会在测试结束后拿到锁并退出。
}
