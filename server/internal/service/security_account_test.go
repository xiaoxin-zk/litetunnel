package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func TestUpdateAdminBumpsTokenVersionOnRoleChange(t *testing.T) {
	svc := newTestServices(t, nil)

	target := mustAdmin(t, svc, "superone", "super")
	operator := mustAdmin(t, svc, "operatorone", "super")

	role := "auditor"
	if err := svc.UpdateAdmin(target.ID, operator.ID, AdminUpdateInput{Role: &role}); err != nil {
		t.Fatalf("降级失败: %v", err)
	}

	got := loadAdmin(t, svc, target.ID)
	if got.Role != "auditor" {
		t.Fatalf("角色 = %q，期望 auditor", got.Role)
	}
	if got.TokenVersion != target.TokenVersion+1 {
		t.Fatalf("角色变更后令牌版本 = %d，期望 %d：不递增的话，旧令牌在过期前仍是 super",
			got.TokenVersion, target.TokenVersion+1)
	}
}

func TestUpdateAdminBumpsTokenVersionOnStatusChange(t *testing.T) {
	svc := newTestServices(t, nil)

	target := mustAdmin(t, svc, "superone", "operator")
	operator := mustAdmin(t, svc, "operatorone", "super")

	status := "disabled"
	if err := svc.UpdateAdmin(target.ID, operator.ID, AdminUpdateInput{Status: &status}); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if got := loadAdmin(t, svc, target.ID); got.TokenVersion != target.TokenVersion+1 {
		t.Fatalf("状态变更后令牌版本 = %d，期望 %d", got.TokenVersion, target.TokenVersion+1)
	}
}

func TestUpdateAdminKeepsTokenVersionWhenNothingChanges(t *testing.T) {
	svc := newTestServices(t, nil)

	target := mustAdmin(t, svc, "operatorone", "operator")
	operator := mustAdmin(t, svc, "superone", "super")

	nickname := "换个昵称"
	if err := svc.UpdateAdmin(target.ID, operator.ID, AdminUpdateInput{Nickname: &nickname}); err != nil {
		t.Fatalf("改昵称失败: %v", err)
	}
	if got := loadAdmin(t, svc, target.ID); got.TokenVersion != target.TokenVersion {
		t.Fatalf("只改昵称不该动令牌版本：%d → %d", target.TokenVersion, got.TokenVersion)
	}

	same := "operator"
	if err := svc.UpdateAdmin(target.ID, operator.ID, AdminUpdateInput{Role: &same}); err != nil {
		t.Fatalf("重复设置角色失败: %v", err)
	}
	if got := loadAdmin(t, svc, target.ID); got.TokenVersion != target.TokenVersion {
		t.Fatalf("角色值没变就不该动令牌版本：%d → %d", target.TokenVersion, got.TokenVersion)
	}
}

func TestAdminSetUserStatusBlocksWithoutBorrowingQuotaFlag(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "blockuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	svc.Runtime.RecordLogin("run-block-1", u.ID, u.Username)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("禁用后应处于「账号不可用」状态")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("禁用不该借用超额标记：那个值会被采集按配额重算，禁用因此可能被悄悄解除")
	}
	if _, ok := svc.Runtime.LookupSession("run-block-1"); ok {
		t.Error("禁用时应撤销该用户的运行时会话")
	}

	svc.refreshQuotaFlags()
	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("采集之后禁用被解除了——这正是要防的：配额没超限的禁用用户被重新放行")
	}

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if svc.Runtime.IsUserBlocked(u.ID) {
		t.Error("启用后应解除「账号不可用」")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("重新启用后应立即按真实配额重算，而不是等下一轮采集")
	}
}

func TestRefreshQuotaFlagsSyncsBlockedFromDB(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "disableduser", Password: "not-used", Status: model.UserStatusDisabled}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：内存里不该有该用户的禁用标记")
	}

	svc.refreshQuotaFlags()

	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("采集应把库里的禁用状态同步到内存，否则重启后禁用会失效")
	}
}

func TestCaptchaThresholdSurvivesLogBacklog(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyLoginCaptchaAfter: "3"}); err != nil {
		t.Fatalf("设置阈值失败: %v", err)
	}

	const account = "backlog-user"
	for i := 0; i < loginLogBuffer+1; i++ {
		svc.RecordLogin(LoginAttempt{
			Kind:     model.LoginKindUser,
			Username: account,
			Result:   model.LoginResultBadCred,
		})
	}

	if got := len(svc.loginLogCh); got != loginLogBuffer {
		t.Fatalf("前置条件：队列应当已被灌满，实际 %d", got)
	}
	if n := svc.CountRecentFailedLogins(model.LoginKindUser, account, 30*time.Minute); n != 0 {
		t.Fatalf("前置条件：此刻不该有登录日志落库，实际 %d 条", n)
	}

	if !svc.CaptchaRequired("login", account) {
		t.Fatal("日志积压丢光之后，账号级验证码要求必须仍然生效")
	}
	if svc.CaptchaRequired("login", "innocent-user") {
		t.Fatal("从未失败过的账号不该被要求验证码")
	}
}

func TestAdminCannotEnableTunnelWithoutHTTPSEntry(t *testing.T) {
	svc := newTestServices(t, &config.Config{
		TunnelDomain:   "tunnel.example.com",
		UserPublicURL:  "https://panel.example.com",
		HTTPSProxyMode: tlscfg.HTTPSModeEdge,
	})

	u := &model.User{Username: "tunnelowner", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID:    u.ID,
		Name:      "lt_owner.web",
		Type:      model.ProxyTypeHTTPS,
		Subdomain: "web",
		Status:    model.TunnelStatusDisabled,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); !errors.Is(err, ErrNoHTTPSProxyEntry) {
		t.Fatalf("边缘模式下管理员不该能启用 HTTPS 隧道，实际 %v", err)
	}
	var got model.Tunnel
	if err := svc.DB.First(&got, tun.ID).Error; err != nil {
		t.Fatalf("回读隧道失败: %v", err)
	}
	if got.Status != model.TunnelStatusDisabled {
		t.Fatalf("被拒绝时状态不能变，实际 %q", got.Status)
	}

	if err := svc.SetTunnelStatus(u.ID, tun.ID, model.TunnelStatusActive); !errors.Is(err, ErrNoHTTPSProxyEntry) {
		t.Fatalf("用户侧也不该能启用，实际 %v", err)
	}

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用不该被入口检查挡住，实际 %v", err)
	}
}

func TestLastSuperAdminDemotionIsAtomic(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newSuperAdmin(t, svc, "super-a")
	b := newSuperAdmin(t, svc, "super-b")

	demote := func(target, operator *model.Admin) error {
		role := "operator"
		return svc.UpdateAdmin(target.ID, operator.ID, AdminUpdateInput{Role: &role})
	}

	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = demote(b, a) }()
	go func() { defer wg.Done(); errs[1] = demote(a, b) }()
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("并发互相降级应当恰好成功一次，实际成功 %d 次（errs=%v）", ok, errs)
	}
	if n := countActiveSupers(t, svc); n < 1 {
		t.Fatalf("必须至少保留一个可用的超级管理员，实际剩 %d 个", n)
	}
}

func TestLastSuperAdminDeleteIsAtomic(t *testing.T) {
	svc := newTestServices(t, nil)
	a := newSuperAdmin(t, svc, "super-a")
	b := newSuperAdmin(t, svc, "super-b")

	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = svc.DeleteAdmin(b.ID, a.ID) }()
	go func() { defer wg.Done(); errs[1] = svc.DeleteAdmin(a.ID, b.ID) }()
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("并发互相删除应当恰好成功一次，实际成功 %d 次（errs=%v）", ok, errs)
	}
	if n := countActiveSupers(t, svc); n < 1 {
		t.Fatalf("必须至少保留一个可用的超级管理员，实际剩 %d 个", n)
	}
}

func TestDomainSettingsRejectLineBreaks(t *testing.T) {
	svc := newTestServices(t, nil)

	targets := []SettingKey{
		KeyDomainPanel, KeyDomainTunnel, KeyDomainACMEEmail, KeyDomainDNSProvider,
		KeyDomainDNSArgs, KeyDomainDNSCredential, KeyDomainHTTPSMode,
		KeyDomainExpectedIP, KeyDomainHelperAddr, KeyDomainHelperToken,
	}
	for _, k := range targets {
		err := svc.Settings.SetMany(map[SettingKey]string{
			k: "value\nLT_CADDY_IMAGE=evil:latest",
		})
		if !errors.Is(err, ErrInvalidParam) {
			t.Fatalf("%s 允许了换行注入，err=%v", k, err)
		}
		if got := svc.Settings.Get(k); strings.Contains(got, "evil") {
			t.Fatalf("%s 的注入值被写进了缓存", k)
		}
	}

	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainDNSProvider: "cloudflare"}); err != nil {
		t.Fatalf("正常值不该被拒绝: %v", err)
	}
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyRegisterTerms: "第一行\n第二行"}); err != nil {
		t.Fatalf("多行文本不该被 SingleLine 规则拦住: %v", err)
	}
}

func TestAdminSetUserGroupDoesNotDeadlock(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "groupuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	g := &model.Group{
		Name: "测试分组", MaxTunnels: 2, MaxPorts: 2,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20,
		AllowProtocols: "tcp", IsDefault: true,
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("调整分组失败: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("AdminSetUserGroup 卡住了：配额刷新必须在事务提交之后，否则 SQLite 单连接会自锁")
	}
}

func TestAdminSetUserGroupRejectsUnknownUser(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{
		Name: "测试分组", MaxTunnels: 2, MaxPorts: 2,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20,
		AllowProtocols: "tcp", IsDefault: true,
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}

	if err := svc.AdminSetUserGroup(999999, g.ID, GroupExpiry{}); err == nil {
		t.Fatal("用户不存在时必须报错，而不是静默成功")
	}
}

func TestRedeemRefreshesQuotaFlag(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "redeemuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"traffic_quota": 1, "traffic_used": 2}).Error; err != nil {
		t.Fatalf("设置配额失败: %v", err)
	}
	svc.refreshQuotaFor(u.ID)
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("前置条件不成立：该用户应处于超额状态")
	}

	code := &model.RedeemCode{
		Code: "TEST-TRAFFIC-0001", Type: model.RedeemTypeTraffic,
		Value: 1 << 30, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建兑换码失败: %v", err)
	}

	if _, err := svc.Redeem(u.ID, code.Code, "127.0.0.1"); err != nil {
		t.Fatalf("兑换失败: %v", err)
	}

	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("兑换流量后应立即解除超额，而不是等下一轮采集")
	}
}

func TestAdminCreateUserBypassesPublicRegistration(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterEnabled: "false",
		KeyRegisterCaptcha: "true",
	}); err != nil {
		t.Fatalf("设置注册开关失败: %v", err)
	}

	if _, err := svc.Register(RegisterInput{
		Username: "publicuser", Password: "Passw0rd123", AgreedTerms: true,
	}); err == nil {
		t.Fatal("前置条件：关闭注册后公开注册应被拒绝")
	}

	u, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "adminmade", Password: "Passw0rd123", Email: "made@example.com",
		Remark: "管理员建号",
	})
	if err != nil {
		t.Fatalf("管理员建号不应受公开注册准入约束，实际失败: %v", err)
	}
	if u.Username != "adminmade" || u.Status != model.UserStatusActive {
		t.Fatalf("建出来的账号不对: %+v", u)
	}
	if u.APIKeyHash == "" {
		t.Error("建号应同时生成 API Key（客户端只用它登录）")
	}
	if u.EmailVerified {
		t.Error("管理员填的邮箱没走过验证码，不该标成已验证")
	}
}

func TestAdminCreateUserValidatesData(t *testing.T) {
	svc := newTestServices(t, nil)

	if _, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "ok_name", Password: "short",
	}); err == nil {
		t.Error("密码过短仍应被拒绝")
	}
	if _, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "bad name!", Password: "Passw0rd123",
	}); err == nil {
		t.Error("用户名非法字符仍应被拒绝")
	}

	if _, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "dupuser", Password: "Passw0rd123",
	}); err != nil {
		t.Fatalf("首次建号失败: %v", err)
	}
	if _, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "dupuser", Password: "Passw0rd123",
	}); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("重名应返回 ErrUsernameTaken，实际 %v", err)
	}
}

func TestPasswordResetKeepsOldTokenWhenDeliveryFails(t *testing.T) {
	svc, fm := newMailTestServices(t)
	fm.setFail(true)

	const email = "resetkeep@example.com"
	u := &model.User{
		Username: "resetkeep", Password: "not-used",
		Email: email, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	old := model.PasswordResetToken{
		UserID: u.ID, TokenHash: "old-token-hash",
		ExpireAt: time.Now().Add(30 * time.Minute),
	}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("建旧令牌失败: %v", err)
	}

	if err := svc.requestPasswordReset(u.Username, "127.0.0.1", "https://example.com"); err != nil {
		t.Fatalf("找回密码必须保持静默（否则可用于枚举账号），实际返回 %v", err)
	}

	for i := 0; i < mailMaxAttempts+1; i++ {
		deliverAll(svc)
		if err := svc.DB.Model(&model.MailOutbox{}).
			Where("to_addr = ?", email).
			Update("next_at", time.Now().Add(-time.Second)).Error; err != nil {
			t.Fatalf("调整重试时间失败: %v", err)
		}
	}

	var got model.PasswordResetToken
	if err := svc.DB.First(&got, old.ID).Error; err != nil {
		t.Fatalf("读旧令牌失败: %v", err)
	}
	if got.UsedAt != nil {
		t.Error("投递失败不该作废旧令牌：用户手上的链接全部失效，而接口说「已发送」")
	}

	var n int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		t.Fatalf("统计令牌失败: %v", err)
	}
	if n != 1 {
		t.Errorf("投递失败不该产生新令牌，实际共 %d 条", n)
	}
}

func TestUpdateGroupRefreshesQuotaFlags(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{
		Name: "配额组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 100, BandwidthLimit: 1 << 20, AllowProtocols: "tcp",
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u := &model.User{
		Username: "groupquota", Password: "not-used",
		Status: model.UserStatusActive, GroupID: g.ID, TrafficUsed: 200,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	svc.refreshQuotaFor(u.ID)
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("前置条件：已用 200 > 配额 100，应处于超额状态")
	}

	if _, err := svc.UpdateGroup(g.ID, GroupInput{
		Name: "配额组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20, AllowProtocols: "tcp",
	}); err != nil {
		t.Fatalf("更新分组失败: %v", err)
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("调高配额后应立即解除超额，而不是等下一轮采集")
	}

	if _, err := svc.UpdateGroup(g.ID, GroupInput{
		Name: "配额组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 10, BandwidthLimit: 1 << 20, AllowProtocols: "tcp",
	}); err != nil {
		t.Fatalf("再次更新分组失败: %v", err)
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("调低配额后应立即开始拦截，而不是等下一轮采集")
	}
}

func TestWriteAuditReportsFailure(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.WriteAudit(1, "admin", "user.update", "user", "2", "detail", "127.0.0.1"); err != nil {
		t.Fatalf("正常写入不该报错: %v", err)
	}

	if err := svc.DB.Migrator().DropTable(&model.AuditLog{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	if err := svc.WriteAudit(1, "admin", "user.update", "user", "2", "detail", "127.0.0.1"); err == nil {
		t.Fatal("审计写失败必须返回错误，否则调用方无从知道记录丢了")
	}
}

func TestRunMaintenancePrunesExpiredCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	old := time.Now().Add(-48 * time.Hour)
	for i, createdAt := range []time.Time{old, time.Now()} {
		rec := model.EmailCode{
			Email: fmt.Sprintf("prune%d@example.com", i), Scene: EmailSceneRegister,
			CodeHash: "h", ExpireAt: createdAt.Add(10 * time.Minute), CreatedAt: createdAt,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建验证码失败: %v", err)
		}
	}
	for i, createdAt := range []time.Time{old, time.Now()} {
		rec := model.PasswordResetToken{
			UserID: uint(i + 1), TokenHash: fmt.Sprintf("tok-%d", i),
			ExpireAt: createdAt.Add(30 * time.Minute), CreatedAt: createdAt,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建令牌失败: %v", err)
		}
	}
	for _, rec := range []model.MailOutbox{
		{To: "a@example.com", Subject: "s", Kind: model.MailKindResetLink, Status: model.MailFailed,
			NextAt: time.Now(), UpdatedAt: time.Now().Add(-8 * 24 * time.Hour)},
		{To: "b@example.com", Subject: "s", Kind: model.MailKindResetLink, Status: model.MailFailed,
			NextAt: time.Now(), UpdatedAt: time.Now()},
		{To: "c@example.com", Subject: "s", Kind: model.MailKindResetLink, Status: model.MailSent,
			NextAt: time.Now(), UpdatedAt: time.Now().Add(-2 * time.Hour)},
	} {
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建邮件记录失败: %v", err)
		}
	}

	svc.RunMaintenance()

	var codes int64
	if err := svc.DB.Model(&model.EmailCode{}).Count(&codes).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if codes != 1 {
		t.Errorf("过期验证码应被清理、近期的保留，实际剩 %d 条（期望 1）", codes)
	}

	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).Count(&tokens).Error; err != nil {
		t.Fatalf("统计令牌失败: %v", err)
	}
	if tokens != 1 {
		t.Errorf("过期令牌应被清理、近期的保留，实际剩 %d 条（期望 1）", tokens)
	}

	var mails int64
	if err := svc.DB.Model(&model.MailOutbox{}).Count(&mails).Error; err != nil {
		t.Fatalf("统计邮件失败: %v", err)
	}
	if mails != 2 {
		t.Errorf("只该清掉超过保留期的失败邮件，实际剩 %d 条（期望 2）", mails)
	}
	var stale int64
	if err := svc.DB.Model(&model.MailOutbox{}).Where("to_addr = ?", "a@example.com").
		Count(&stale).Error; err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if stale != 0 {
		t.Error("超过保留期的失败邮件应被清理（否则这张表只增不减）")
	}
}

func TestRunMaintenanceDrainsBacklog(t *testing.T) {
	svc := newTestServices(t, nil)

	old := time.Now().Add(-48 * time.Hour)
	total := maintenanceBatchSize + 50
	for i := 0; i < total; i++ {
		rec := model.EmailCode{
			Email: fmt.Sprintf("batch%d@example.com", i), Scene: EmailSceneRegister,
			CodeHash: "h", ExpireAt: old.Add(10 * time.Minute), CreatedAt: old,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建验证码失败: %v", err)
		}
	}

	svc.RunMaintenance()

	var left int64
	if err := svc.DB.Model(&model.EmailCode{}).Count(&left).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if left != 0 {
		t.Fatalf("一轮维护应在预算内清完积压，实际剩 %d 条", left)
	}
}

func TestPruneBatchIsBatched(t *testing.T) {
	svc := newTestServices(t, nil)

	old := time.Now().Add(-48 * time.Hour)
	total := maintenanceBatchSize + 50
	for i := 0; i < total; i++ {
		rec := model.EmailCode{
			Email: fmt.Sprintf("batch%d@example.com", i), Scene: EmailSceneRegister,
			CodeHash: "h", ExpireAt: old.Add(10 * time.Minute), CreatedAt: old,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建验证码失败: %v", err)
		}
	}

	n := svc.pruneBatch(context.Background(), "过期验证码", &model.EmailCode{},
		"created_at < ?", time.Now().Add(-emailCodeRetention))
	if n != maintenanceBatchSize {
		t.Fatalf("单批最多删 %d 条，实际 %d", maintenanceBatchSize, n)
	}

	var left int64
	if err := svc.DB.Model(&model.EmailCode{}).Count(&left).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if want := int64(total - maintenanceBatchSize); left != want {
		t.Fatalf("剩余应为 %d 条，实际 %d", want, left)
	}
}

func TestDeliveredCodeIsValidFromDeliveryTime(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "ttl@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	var queued model.MailOutbox
	if err := svc.DB.Where("to_addr = ?", email).First(&queued).Error; err != nil {
		t.Fatalf("读发件箱失败: %v", err)
	}
	if !strings.Contains(queued.Payload, "ttl_seconds") {
		t.Fatalf("载荷应记录 TTL（有效期从送达起算），实际 %s", queued.Payload)
	}
	if strings.Contains(queued.Payload, "expire_at") {
		t.Fatalf("载荷不该记录绝对过期时间（排队久了就会过期），实际 %s", queued.Payload)
	}

	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", queued.ID).
		Update("created_at", time.Now().Add(-2*time.Hour)).Error; err != nil {
		t.Fatalf("调整入队时间失败: %v", err)
	}

	deliverAll(svc)

	var rec model.EmailCode
	if err := svc.DB.Where("email = ?", email).Order("id desc").First(&rec).Error; err != nil {
		t.Fatalf("送达后应创建验证码: %v", err)
	}
	if rec.ExpireAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("有效期应从送达时刻起算，实际 %s（距今 %s）",
			rec.ExpireAt, time.Until(rec.ExpireAt).Round(time.Second))
	}
}

func TestCreateTunnelWaitsForUserLock(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "lockuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	g := &model.Group{
		Name: "测试分组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20,
		AllowProtocols: "tcp", IsDefault: true,
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}

	lock := svc.userLock(u.ID)
	lock.Lock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = svc.CreateTunnel(u, TunnelInput{
			Name: "mc", Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565,
		})
	}()

	select {
	case <-done:
		t.Fatal("删除用户持锁期间，建隧道必须先等待——否则会建给一个正在被删除的账号")
	case <-time.After(300 * time.Millisecond):
	}

	lock.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("释放锁之后建隧道应立即继续")
	}
}

func TestRedeemWritesAuditRecords(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "audituser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	countRecords := func(result string) int64 {
		t.Helper()
		var n int64
		if err := svc.DB.Model(&model.RedeemRecord{}).
			Where("user_id = ? AND result = ?", u.ID, result).Count(&n).Error; err != nil {
			t.Fatalf("统计流水失败: %v", err)
		}
		return n
	}

	if _, err := svc.Redeem(u.ID, "NO-SUCH-CODE-0000", "127.0.0.1"); err == nil {
		t.Fatal("无效兑换码应报错")
	}
	if got := countRecords("invalid"); got != 1 {
		t.Fatalf("无效尝试应留下 1 条审计，实际 %d 条（写在事务里会被回滚掉）", got)
	}

	code := &model.RedeemCode{
		Code: "TEST-AUDIT-0001", Type: model.RedeemTypeTraffic,
		Value: 1 << 20, MaxUses: 1, Status: model.RedeemStatusUnused,
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建兑换码失败: %v", err)
	}
	if _, err := svc.Redeem(u.ID, code.Code, "127.0.0.1"); err != nil {
		t.Fatalf("兑换失败: %v", err)
	}
	if got := countRecords("success"); got != 1 {
		t.Fatalf("成功兑换应留下 1 条流水，实际 %d 条", got)
	}
}

func TestRuntimeGCPrunesOrphanTouchAt(t *testing.T) {
	svc := newTestServices(t, nil)

	if !svc.Runtime.ShouldTouch("run-orphan", time.Minute) {
		t.Fatal("前置条件：首次心跳应允许落库")
	}
	if _, ok := svc.Runtime.touchAt["run-orphan"]; !ok {
		t.Fatal("前置条件：节流记录应已写入")
	}

	backdateTouchAt(t, svc.Runtime, "run-orphan", time.Hour)
	svc.Runtime.GC(10 * time.Minute)

	if _, ok := svc.Runtime.touchAt["run-orphan"]; ok {
		t.Error("孤儿节流记录也要按时间清理，否则客户端反复重连会让它只增不减")
	}
}

func TestSettingStoreReloadIfChanged(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	changed, err := svc.Settings.ReloadIfChanged()
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if changed {
		t.Fatal("没有写入时不该判定为变化")
	}

	other := NewSettingStore(svc.DB, cfg)
	if err := other.SetMany(map[SettingKey]string{KeyPortReserved: "30000-30010"}); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}
	if got := svc.Settings.Get(KeyPortReserved); got == "30000-30010" {
		t.Fatal("本实例的缓存不该被另一个实例的写入自动改动（这正是需要轮询的原因）")
	}

	changed, err = svc.Settings.ReloadIfChanged()
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !changed {
		t.Fatal("其他实例改了配置，本实例应重新载入")
	}
	if got := svc.Settings.Get(KeyPortReserved); got != "30000-30010" {
		t.Fatalf("应读到新值，实际 %q", got)
	}
}

func TestSettingStoreConcurrentReloadKeepsNewest(t *testing.T) {
	svc := newTestServices(t, &config.Config{})
	settings := svc.Settings

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := settings.ReloadIfChanged(); err != nil {
				return
			}
		}
	}()

	last := ""
	for i := 0; i < 30; i++ {
		last = fmt.Sprintf("%d", 30000+i)
		if err := settings.SetMany(map[SettingKey]string{KeyPortReserved: last}); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("写入配置失败: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if got := settings.Get(KeyPortReserved); got != last {
		t.Fatalf("缓存被更早的快照覆盖了：期望 %q，实际 %q", last, got)
	}
}

func TestAdminDeleteUserRemovesResetMark(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "markorphan", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Create(&model.TrafficResetMark{UserID: u.ID, Gen: 3}).Error; err != nil {
		t.Fatalf("写标记失败: %v", err)
	}

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("删除用户失败: %v", err)
	}

	var n int64
	if err := svc.DB.Model(&model.TrafficResetMark{}).
		Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("删号后不该残留清零代次标记，实际 %d 条", n)
	}
}

func TestPasswordChangeRevokesPendingResetLinks(t *testing.T) {
	svc := newTestServices(t, &config.Config{})

	hashed, err := auth.HashPassword("OldPass123")
	if err != nil {
		t.Fatalf("生成密码哈希失败: %v", err)
	}
	u := &model.User{
		Username: "pwdrevoke", Password: hashed, Status: model.UserStatusActive,
		Email: "pwdrevoke@example.com", EmailVerified: true,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	sum := sha256.Sum256([]byte("old-link-token"))
	tok := &model.PasswordResetToken{
		UserID: u.ID, TokenHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(time.Hour),
	}
	if err := svc.DB.Create(tok).Error; err != nil {
		t.Fatalf("建重置令牌失败: %v", err)
	}
	mail := &model.MailOutbox{
		To: u.Email, Subject: "reset", Kind: model.MailKindResetLink,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(mail).Error; err != nil {
		t.Fatalf("建重置邮件失败: %v", err)
	}

	code := &model.EmailCode{
		Email: u.Email, Scene: EmailSceneReset, CodeHash: "reset-code-hash",
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(code).Error; err != nil {
		t.Fatalf("建找回验证码失败: %v", err)
	}
	codeMail := &model.MailOutbox{
		To: u.Email, Subject: "code", Kind: model.MailKindEmailCodeReset,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(codeMail).Error; err != nil {
		t.Fatalf("建找回验证码邮件失败: %v", err)
	}

	if err := svc.UpdatePassword(u.ID, "OldPass123", "NewPass456"); err != nil {
		t.Fatalf("改密失败: %v", err)
	}

	var got model.PasswordResetToken
	if err := svc.DB.First(&got, tok.ID).Error; err != nil {
		t.Fatalf("读令牌失败: %v", err)
	}
	if got.UsedAt == nil {
		t.Fatal("改密后未使用的重置令牌必须作废，否则旧链接还能再改一次密码")
	}

	var m model.MailOutbox
	if err := svc.DB.First(&m, mail.ID).Error; err != nil {
		t.Fatalf("读邮件失败: %v", err)
	}
	if m.Status != model.MailFailed {
		t.Fatalf("排队中的重置邮件应作废，实际状态 %q", m.Status)
	}
	if m.Payload != "" {
		t.Fatal("作废的邮件必须清掉载荷里的凭据参数")
	}

	var c model.EmailCode
	if err := svc.DB.First(&c, code.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if c.UsedAt == nil {
		t.Fatal("改密后未使用的找回验证码必须作废")
	}
	var cm model.MailOutbox
	if err := svc.DB.First(&cm, codeMail.ID).Error; err != nil {
		t.Fatalf("读验证码邮件失败: %v", err)
	}
	if cm.Status != model.MailFailed {
		t.Fatalf("排队中的找回验证码邮件应作废，实际状态 %q", cm.Status)
	}

	if err := svc.ResetPassword("old-link-token", "Another123", "127.0.0.1"); !errors.Is(err, ErrResetTokenInvalid) {
		t.Fatalf("旧链接必须失效，实际 %v", err)
	}
}

func TestResetCodeActivationRejectsLegacyPayload(t *testing.T) {
	svc := newTestServices(t, &config.Config{})

	u := &model.User{
		Username: "legacycode", Password: "not-used", Status: model.UserStatusActive,
		Email: "legacycode@example.com", EmailVerified: true, TokenVersion: 3,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	payload, err := json.Marshal(emailCodePayload{
		Email: u.Email, Scene: EmailSceneReset, CodeHash: "legacy-code", TTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("序列化载荷失败: %v", err)
	}
	row := &model.MailOutbox{
		To: u.Email, Subject: "code", Kind: model.MailKindEmailCodeReset,
		Status: model.MailActivating, ClaimToken: "claim-legacy",
		Payload: string(payload), NextAt: time.Now(),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建邮件失败: %v", err)
	}

	if err := svc.activateEmailCode(*row, "claim-legacy"); !errors.Is(err, errMailActionObsolete) {
		t.Fatalf("改过密码的账号，旧载荷必须作废，实际 %v", err)
	}
	var n int64
	if err := svc.DB.Model(&model.EmailCode{}).Where("email = ?", u.Email).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("作废的邮件不该创建验证码，实际 %d 条", n)
	}
}

func TestResetActivationRejectsAfterPasswordChange(t *testing.T) {
	svc := newTestServices(t, &config.Config{})

	u := &model.User{
		Username: "activationstale", Password: "not-used", Status: model.UserStatusActive,
		Email: "activationstale@example.com", EmailVerified: true, TokenVersion: 2,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	queuedVersion := 1
	payload, err := json.Marshal(resetLinkPayload{
		UserID: u.ID, TokenHash: "deadbeef", TTLSeconds: 600,
		TokenVersion: &queuedVersion,
	})
	if err != nil {
		t.Fatalf("序列化载荷失败: %v", err)
	}
	row := &model.MailOutbox{
		To: u.Email, Subject: "reset", Kind: model.MailKindResetLink,
		Status: model.MailActivating, ClaimToken: "claim-1",
		Payload: string(payload), NextAt: time.Now(),
	}
	if err := svc.DB.Create(row).Error; err != nil {
		t.Fatalf("建邮件失败: %v", err)
	}

	err = svc.activateResetToken(*row, "claim-1")
	if !errors.Is(err, errMailActionObsolete) {
		t.Fatalf("入队后改过密码的邮件必须作废，实际 %v", err)
	}

	var n int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("作废的邮件不该创建令牌，实际 %d 条", n)
	}
}
