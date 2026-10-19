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

	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainHTTPSMode: tlscfg.HTTPSModeE2E}); err != nil {
		t.Fatalf("写入设置失败: %v", err)
	}
	if svc.HTTPSProxyEntryEnabled() {
		t.Fatal("只保存、还没下发时不该认为 HTTPS 隧道已经有入口")
	}
	if !svc.DomainPending() {
		t.Fatal("保存之后应当处于「待下发」状态，界面要据此提示")
	}

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

	httpTunnel := &model.Tunnel{Type: model.ProxyTypeHTTP, Subdomain: "web"}
	if got := svc.TunnelPublicAddr(httpTunnel); got != "https://web.tunnel.example.com" {
		t.Fatalf("HTTP 隧道的地址不该带端口，实际 %q", got)
	}
	tcpTunnel := &model.Tunnel{Type: model.ProxyTypeTCP, RemotePort: 23456}
	if got := svc.TunnelPublicAddr(tcpTunnel); got != "203.0.113.10:23456" {
		t.Fatalf("TCP 隧道地址不对，实际 %q", got)
	}
}

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
	if got := s.Get(KeyDomainTunnel); got != "panel-set.example.com" || !s.hasRow(KeyDomainTunnel) {
		t.Fatalf("期望值不该被动过，实际 %q", got)
	}

	svc := New(db, cfg)
	if got := svc.TunnelDomain(); got != "env.example.com" {
		t.Fatalf("没有下发记录时运行期必须以 .env 为准，实际 %q", got)
	}
	if !svc.DomainPending() {
		t.Fatal("库里的期望值与 .env 不一致时必须显示「待下发」，否则等于谎报已生效")
	}

	if err := s.SetMany(map[SettingKey]string{KeyDomainAppliedTunnel: "evil.example.com"}); err == nil {
		t.Fatal("「已生效」这一组不该允许通过设置接口写入")
	}
	if _, ok := s.AllForAdmin()[string(KeyDomainAppliedTunnel)]; ok {
		t.Fatal("「已生效」这一组不该出现在管理端返回中")
	}
}

func TestEmptyTunnelDomainMeansDisabled(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "tunnel.example.com",
		UserPublicURL: "https://panel.example.com",
	})

	if got := svc.DesiredTunnelDomain(); got != "tunnel.example.com" {
		t.Fatalf("没有行时应当以 .env 为准，实际 %q", got)
	}

	if err := svc.UpdateSettings(map[SettingKey]string{KeyDomainTunnel: ""}); err != nil {
		t.Fatalf("清空隧道根域名失败: %v", err)
	}
	if got := svc.DesiredTunnelDomain(); got != "" {
		t.Fatalf("清空后应当表达「关闭」，不该回落到 .env 得到 %q", got)
	}
	if got := svc.TunnelDomain(); got != "tunnel.example.com" {
		t.Fatalf("只保存未下发时应继续按 .env 判权，实际 %q", got)
	}
	if !svc.DomainPending() {
		t.Fatal("「已关闭」还没下发时必须显示「待下发」")
	}

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

func TestDomainPendingCoversCertificateSettings(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:  "tunnel.example.com",
		UserPublicURL: "https://panel.example.com",
	})

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
		applyDomain(t, svc)
		if svc.DomainPending() {
			t.Fatalf("「%s」下发之后不该仍是「待下发」", st.name)
		}
	}

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

	raw := errors.New("UNIQUE constraint failed: lt_tunnels.remote_port")
	if got := describeTunnelWriteError(raw); got != raw {
		t.Fatalf("端口冲突不该被改写，得到 %v", got)
	}
}

func TestApplyDomainConfigWaitsForDomainMu(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.domainMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = svc.ApplyDomainConfig(context.Background(), true)
	}()

	select {
	case <-done:
		t.Fatal("另一个下发还没结束时，第二次下发不应当进入临界区")
	case <-time.After(50 * time.Millisecond):
	}

	svc.domainMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("锁释放后下发应当继续完成")
	}
}

func TestUpdateSettingsDomainSaveWaitsForApply(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.domainMu.Lock()
	defer svc.domainMu.Unlock()

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

	doneDomain := make(chan error, 1)
	go func() { doneDomain <- svc.UpdateSettings(map[SettingKey]string{KeyDomainACMEEmail: "ops@example.com"}) }()
	select {
	case <-doneDomain:
		t.Fatal("改域名组的保存不该在下发进行中完成")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPanelDomainAllowsPort(t *testing.T) {
	svc := newTestServices(t, &config.Config{UserPublicURL: "http://203.0.113.10:7848"})
	if got := svc.Settings.Get(KeyDomainPanel); got != "203.0.113.10:7848" {
		t.Fatalf("面板域名默认值应保留端口，实际 %q", got)
	}
	if err := svc.UpdateSettings(map[SettingKey]string{KeyDomainPanel: "203.0.113.10:7848"}); err != nil {
		t.Fatalf("带端口的面板域名不该被拒: %v", err)
	}
	if err := checkPanelDomain("panel.example.com:8443"); err != nil {
		t.Fatalf("合法端口被拒: %v", err)
	}
	for _, bad := range []string{
		"panel.example.com:0",
		"panel.example.com:70000",
		"panel.example.com:abc",
		"panel.example.com:",
		"2001:db8::1",
	} {
		if err := checkPanelDomain(bad); err == nil {
			t.Fatalf("%q 应被判为非法", bad)
		}
	}
}
