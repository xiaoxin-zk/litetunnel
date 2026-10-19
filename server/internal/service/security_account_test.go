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

// TestUpdateAdminBumpsTokenVersionOnRoleChange 覆盖「降级不生效」。
//
// AdminAuth 的授权读的是**令牌里的角色**，而令牌在过期前一直有效。
// 改角色时若不递增令牌版本，被降级的超级管理员手里那枚旧令牌
// 依然能走 super 路由——降级形同没做。
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

// TestUpdateAdminBumpsTokenVersionOnStatusChange 禁用同样要让旧令牌失效。
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

// TestUpdateAdminKeepsTokenVersionWhenNothingChanges 覆盖反面：
// 只改昵称、或把角色重复设置成同一个值，都不该把人踢下线。
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

// TestAdminSetUserStatusBlocksWithoutBorrowingQuotaFlag 覆盖「禁用被采集解除」。
//
// 禁用原先靠把超额标记强制置 true 实现，而超额标记会被每轮流量采集按配额
// 重算——配额没超限的禁用用户，在下一次成功采集后就被重新放行了。
// 现象是「禁用是否生效取决于采集有没有跑过」，随机且无法复现。
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

	// 关键一步：跑一轮配额刷新（等价于一次成功的流量采集）。
	svc.refreshQuotaFlags()
	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("采集之后禁用被解除了——这正是要防的：配额没超限的禁用用户被重新放行")
	}

	// 重新启用：解除禁用，并按真实配额重算超额标记。
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

// TestRefreshQuotaFlagsSyncsBlockedFromDB 覆盖重启后的禁用状态。
//
// 进程重启后内存是空的，而插件热路径只查内存。不在采集里按库里的账号状态
// 补齐禁用标记的话，已禁用的账号在重启后会重新被放行，直到管理员再动一次。
func TestRefreshQuotaFlagsSyncsBlockedFromDB(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "disableduser", Password: "not-used", Status: model.UserStatusDisabled}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 模拟刚重启：内存里什么都不知道。
	if svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：内存里不该有该用户的禁用标记")
	}

	svc.refreshQuotaFlags()

	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("采集应把库里的禁用状态同步到内存，否则重启后禁用会失效")
	}
}

// TestCaptchaThresholdSurvivesLogBacklog 覆盖「账号级验证码依赖可丢弃的日志」。
//
// 登录日志走容量有限的异步队列，满了就丢弃——这是有意的，写日志绝不能拖住
// 登录判定。但验证码阈值曾经直接查这张表，于是日志一积压，账号级防线就静默
// 失效：不报错、不告警，只是不再要求验证码。而这恰恰发生在数据库慢、攻击最
// 容易得手的时候。
//
// 这里把队列灌满（不启动写库协程），断言阈值仍然生效。
func TestCaptchaThresholdSurvivesLogBacklog(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyLoginCaptchaAfter: "3"}); err != nil {
		t.Fatalf("设置阈值失败: %v", err)
	}

	const account = "backlog-user"
	// 第 loginLogBuffer+1 条起，日志会全部被丢弃。
	for i := 0; i < loginLogBuffer+1; i++ {
		svc.RecordLogin(LoginAttempt{
			Kind:     model.LoginKindUser,
			Username: account,
			Result:   model.LoginResultBadCred,
		})
	}

	// 前置条件：队列确实已经堵死，审计日志一条都没落库。
	if got := len(svc.loginLogCh); got != loginLogBuffer {
		t.Fatalf("前置条件：队列应当已被灌满，实际 %d", got)
	}
	if n := svc.CountRecentFailedLogins(model.LoginKindUser, account, 30*time.Minute); n != 0 {
		t.Fatalf("前置条件：此刻不该有登录日志落库，实际 %d 条", n)
	}

	if !svc.CaptchaRequired("login", account) {
		t.Fatal("日志积压丢光之后，账号级验证码要求必须仍然生效")
	}
	// 对照组：没失败过的账号不受影响。少了它，「一律要求验证码」也能通过。
	if svc.CaptchaRequired("login", "innocent-user") {
		t.Fatal("从未失败过的账号不该被要求验证码")
	}
}

// TestAdminCannotEnableTunnelWithoutHTTPSEntry 覆盖「管理员绕过 HTTPS 入口检查」。
//
// 用户侧的启用路径会确认当前有没有 HTTPS 入口，管理员那条原先自己写了一遍
// 状态变更，于是没有这个检查：平台切回边缘模式后（Caddy 与 frps 上都不再有
// 对应入口），管理员仍能把旧 HTTPS 隧道重新启用，得到一条状态为运行中、
// 实际永远连不上的隧道——用户只看到连不上，后台却一切正常。
//
// 修法是把状态切换收敛到 setTunnelStatus 一处，这里同时验证两条路径。
func TestAdminCannotEnableTunnelWithoutHTTPSEntry(t *testing.T) {
	// 边缘模式：443 由 Caddy 接管，HTTPS 隧道没有入口。
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

	// 管理员路径必须拒绝，且不能偷偷改掉状态。
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

	// 用户侧必须同样拒绝：两条路径一旦分叉，绕过的那条就是攻击面。
	if err := svc.SetTunnelStatus(u.ID, tun.ID, model.TunnelStatusActive); !errors.Is(err, ErrNoHTTPSProxyEntry) {
		t.Fatalf("用户侧也不该能启用，实际 %v", err)
	}

	// 停用方向不受影响：边缘模式下停用一条 HTTPS 隧道仍然是合法操作。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用不该被入口检查挡住，实际 %v", err)
	}
}

// TestLastSuperAdminDemotionIsAtomic 覆盖「两名超级管理员并发互相降级」。
//
// UpdateAdmin 原先有两处「先数一数、再改」：函数开头的快速检查，和最后那条
// 独立的 UPDATE。两者之间没有事务、也没有串行化，于是两个互相降级的请求都会
// 读到「还有对方在」，双双通过 —— 最终一个可用的超级管理员都不剩，
// 谁都登不进后台，只能改数据库才能恢复。
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

	// 恰好成功一次：两次都成功就是上面那个死锁，两次都失败说明守卫把
	// 本来就合法的操作也挡住了。
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

// TestLastSuperAdminDeleteIsAtomic 同上，走删除路径。
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

// TestDomainSettingsRejectLineBreaks 覆盖「凭换行绕过 helper 的变量白名单」。
//
// 面板保存的这几个值会被拼成 .env 的 key=value 交给 helper 写盘，而 Compose
// 的插值（image: ${LT_CADDY_IMAGE:-caddy:2-alpine}）接受任何来自 .env 的键。
// 于是 DNS 凭据里的一个换行就能追加 LT_CADDY_IMAGE，把「面板只能改域名与证书」
// 这条边界整个绕开——helper 用旧镜像校验通过，Compose 却用注入的镜像重建。
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

	// 正常值不受影响：这条守卫不该把功能本身弄坏。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyDomainDNSProvider: "cloudflare"}); err != nil {
		t.Fatalf("正常值不该被拒绝: %v", err)
	}
	// 多行文本类配置不该被这条规则波及（例如注册须知）。
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyRegisterTerms: "第一行\n第二行"}); err != nil {
		t.Fatalf("多行文本不该被 SingleLine 规则拦住: %v", err)
	}
}

// TestAdminSetUserGroupDoesNotDeadlock 覆盖 SQLite 单连接下的自锁。
//
// AdminSetUserGroup 曾经在事务里调用 refreshQuotaFor，而后者要用**主连接**
// 重新查一次用户。SQLite 默认只开一个连接（store.go 的 SetMaxOpenConns(1)）：
// 事务占着那唯一的连接，这次查询永远等不到它释放，事务又在等查询返回——
// 请求就永久卡在那里。管理后台的表现是「点一下没反应」，日志里什么都没有。
//
// 卡死无法用返回值断言，所以这里用超时把它变成一条会失败的用例。
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

// TestAdminSetUserGroupRejectsUnknownUser 覆盖 RowsAffected 检查。
//
// 不看它的话，改一个不存在的用户会「成功」返回，管理员以为改好了，
// 实际什么都没发生。
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

// TestRedeemRefreshesQuotaFlag 覆盖「兑换成功后仍被拒」。
//
// 超额标记是插件实时拦截的依据，平时靠流量采集刷新。兑换恰恰是为了让超额
// 账号重新能用；如果 frps 管理接口不可用、采集刷不动，用户就会看到
// 「兑换成功了，但连接依然被拒」，而且等多久都不会恢复。
func TestRedeemRefreshesQuotaFlag(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "redeemuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// 配额 1 字节、已用 2 字节 → 处于超额状态。
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

// TestAdminCreateUserBypassesPublicRegistration 覆盖「管理员建号永远失败」。
//
// AdminCreateUser 曾经直接调 Register，而 Register 是**公开注册**入口：
// 它要求勾选条款（管理员建号没这个字段，于是 100% 失败，报「请先阅读并同意
// 服务条款」），还受注册开关、人机验证、邮箱域名黑白名单与每日频率限制约束。
// 站点一关注册，管理员就再也建不了号。
func TestAdminCreateUserBypassesPublicRegistration(t *testing.T) {
	svc := newTestServices(t, nil)

	// 关掉公开注册，并打开人机验证：两者都只该影响公开注册。
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterEnabled: "false",
		KeyRegisterCaptcha: "true",
	}); err != nil {
		t.Fatalf("设置注册开关失败: %v", err)
	}

	// 前置条件：公开注册此时确实不可用。
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

// TestAdminCreateUserValidatesData 覆盖反面：绕过的是准入，不是数据校验。
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

// TestPasswordResetKeepsOldTokenWhenDeliveryFails 覆盖同类的令牌版本。
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

// TestUpdateGroupRefreshesQuotaFlags 覆盖「改了分组配额但标记没跟着变」。
//
// Runtime.exceeded 是插件实时拦截的依据，平时靠流量采集刷新。管理员调低
// 配额时用户可能继续建连接，调高配额时已超额用户仍被拒——而 frps 管理接口
// 恰好不可用时，这个标记会一直停在旧值上，等多久都不会恢复。
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

	// 调高配额：该用户应当立刻可以重新建连接。
	if _, err := svc.UpdateGroup(g.ID, GroupInput{
		Name: "配额组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20, AllowProtocols: "tcp",
	}); err != nil {
		t.Fatalf("更新分组失败: %v", err)
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Error("调高配额后应立即解除超额，而不是等下一轮采集")
	}

	// 再调低：应当立刻恢复拦截。
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

// TestWriteAuditReportsFailure 覆盖「审计写入失败被静默忽略」。
//
// 以前是 `_ = s.DB.Create(...)`：写失败既没有日志、也没有任何地方能看出来，
// 于是「操作成功、审计缺失」可以静默存在——出事之后去查审计，只会发现那段时间
// 什么都没有，而且分不清是「没人操作」还是「记录没写进去」。
func TestWriteAuditReportsFailure(t *testing.T) {
	svc := newTestServices(t, nil)

	// 正常写入应当成功。
	if err := svc.WriteAudit(1, "admin", "user.update", "user", "2", "detail", "127.0.0.1"); err != nil {
		t.Fatalf("正常写入不该报错: %v", err)
	}

	// 制造写入失败：删掉审计表。
	if err := svc.DB.Migrator().DropTable(&model.AuditLog{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	if err := svc.WriteAudit(1, "admin", "user.update", "user", "2", "detail", "127.0.0.1"); err == nil {
		t.Fatal("审计写失败必须返回错误，否则调用方无从知道记录丢了")
	}
}

// TestRunMaintenancePrunesExpiredCredentials 覆盖「短期数据没有任何清理路径」。
//
// 验证码过期、令牌用完、邮件发送失败之后，这些行原先会一直留着：公网服务跑上
// 几个月，这几张表会明显变大，索引也跟着变慢。清理必须保留近期记录
// （排查「用户说没收到码」要用），只删过期的。
func TestRunMaintenancePrunesExpiredCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	old := time.Now().Add(-48 * time.Hour)
	// 过期验证码：一旧一新
	for i, createdAt := range []time.Time{old, time.Now()} {
		rec := model.EmailCode{
			Email: fmt.Sprintf("prune%d@example.com", i), Scene: EmailSceneRegister,
			CodeHash: "h", ExpireAt: createdAt.Add(10 * time.Minute), CreatedAt: createdAt,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建验证码失败: %v", err)
		}
	}
	// 重置令牌：一旧一新
	for i, createdAt := range []time.Time{old, time.Now()} {
		rec := model.PasswordResetToken{
			UserID: uint(i + 1), TokenHash: fmt.Sprintf("tok-%d", i),
			ExpireAt: createdAt.Add(30 * time.Minute), CreatedAt: createdAt,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建令牌失败: %v", err)
		}
	}
	// 发件箱：一条 8 天前的失败邮件（该清）、一条刚失败的（该留）、
	// 一条 2 小时前的已送达（在 24 小时保留期内，该留）。
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

// TestRunMaintenanceDrainsBacklog 覆盖「积压长期存在」。
//
// 单条 DELETE 仍按批进行（见 TestPruneBatchIsBatched），但一轮维护会在
// 时间预算内连续分批，直到清空——否则过期记录产生速度高于清理速度时，
// 积压只会越滚越大。
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

// TestPruneBatchIsBatched 覆盖「清理任务一次删太多」。
//
// 一次性大删会长时间占住写锁（SQLite 更是整库阻塞），在业务高峰期尤其危险。
// 单条 DELETE 必须仍然有上限。
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

// TestDeliveredCodeIsValidFromDeliveryTime 覆盖「重试/积压导致收到已过期的码」。
//
// 有效期若从**入队**时刻起算，发件箱重试（1/2/4/8 分钟）加上积压很容易让用户
// 收到一个已经失效的码：邮件正文写着「10 分钟内有效」，实际一到手就过期。
// 所以入队时只存 TTL，有效期从**送达时刻**起算。
func TestDeliveredCodeIsValidFromDeliveryTime(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "ttl@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	// 结构断言：入队时存的是 TTL，而不是一个「入队时刻 + 有效期」的绝对时间。
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

	// 模拟这封信在发件箱里压了很久（进程停机、SMTP 故障等）。
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", queued.ID).
		Update("created_at", time.Now().Add(-2*time.Hour)).Error; err != nil {
		t.Fatalf("调整入队时间失败: %v", err)
	}

	deliverAll(svc)

	var rec model.EmailCode
	if err := svc.DB.Where("email = ?", email).Order("id desc").First(&rec).Error; err != nil {
		t.Fatalf("送达后应创建验证码: %v", err)
	}
	// 有效期必须从现在起算：压了两小时之后送达，用户仍应有完整的 10 分钟。
	if rec.ExpireAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("有效期应从送达时刻起算，实际 %s（距今 %s）",
			rec.ExpireAt, time.Until(rec.ExpireAt).Round(time.Second))
	}
}

// TestCreateTunnelWaitsForUserLock 覆盖「建隧道与删除用户互斥」。
//
// 不互斥的话有个窄窗口：删除流程先读端口清单、再删记录，中间并发建出来的
// 隧道会被删掉而端口不在回收清单里，防火墙规则永久残留。
// 竞态本身无法稳定复现（SQLite 单连接会天然串行化），所以这里直接验证
// 「建隧道确实会先取用户锁」这个结构前提。
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
	lock.Lock() // 模拟「正在删除该用户」

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

// TestRedeemWritesAuditRecords 覆盖兑换流水的两种丢失。
//
//  1. 无效兑换码的审计原先写在业务事务里，紧接着事务回滚——等于从来没记录过。
//     而「有人在撞码」恰恰是风控最关心的信号。
//  2. 成功兑换的流水写入错误被忽略，可能出现「权益已发放但查不到流水」，
//     事后对不上账且无从追查。
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

	// 1) 无效兑换码必须留下审计
	if _, err := svc.Redeem(u.ID, "NO-SUCH-CODE-0000", "127.0.0.1"); err == nil {
		t.Fatal("无效兑换码应报错")
	}
	if got := countRecords("invalid"); got != 1 {
		t.Fatalf("无效尝试应留下 1 条审计，实际 %d 条（写在事务里会被回滚掉）", got)
	}

	// 2) 成功兑换的流水必须落库
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

// TestRuntimeGCPrunesOrphanTouchAt 覆盖「没有对应会话」的节流记录。
//
// 心跳节流对「库里存在、内存里没有」的 runID 同样生效（面板重启后就是这样），
// 这类记录没有任何会话清理路径会经过，只能按时间清。
func TestRuntimeGCPrunesOrphanTouchAt(t *testing.T) {
	svc := newTestServices(t, nil)

	// 只写节流记录，不登记会话。
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

// TestSettingStoreReloadIfChanged 覆盖「多实例共用一个库时配置缓存不刷新」。
//
// 缓存只在本实例写配置后刷新。A 上保存的保留端口，B 会一直按旧值分配，
// 直到 B 重启——所以每个实例都要周期性比对一次库里的原文。
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

	// 另一个实例（同一份库）保存配置。
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

// TestSettingStoreConcurrentReloadKeepsNewest 覆盖「旧快照覆盖新写入」。
//
// 周期刷新与管理员写入并发时，刷新可能先读到旧值、最后才应用：若它晚于
// 写入自己的重载完成，本实例的缓存会短暂回退（刚加的保留端口又变回可分配），
// 直到下一个轮询周期。reloadMu 把「读 → 应用」与「写 → 重载」串行化之后，
// 更早的快照只可能应用在更新的写入之前。
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

// TestAdminDeleteUserRemovesResetMark 覆盖「清零代次标记残留」。
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

// TestPasswordChangeRevokesPendingResetLinks 覆盖「改密后旧重置链接仍可用」。
//
// ResetPassword 校验的是令牌自己的 used_at/expire_at，不看 TokenVersion，
// 所以改密时必须显式撤销未使用的令牌；排队中的重置邮件也要一起作废——
// 它的令牌是送达时才创建的，撤销时还不存在。
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

	// 另一条恢复通道：找回密码的邮箱验证码（含一封排队中的对应邮件）。
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

	// 验证码这条恢复通道同样要撤销：ResetPasswordByEmailCode 只看验证码本身。
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

// TestResetCodeActivationRejectsLegacyPayload 覆盖「升级遗留队列绕过改密保护」。
//
// 升级前入队的找回验证码载荷没有版本快照。账号改过密码（版本 > 1）时，
// 无法证明「期间没改过密码」，必须拒绝激活——缺快照不能成为绕过口。
func TestResetCodeActivationRejectsLegacyPayload(t *testing.T) {
	svc := newTestServices(t, &config.Config{})

	u := &model.User{
		Username: "legacycode", Password: "not-used", Status: model.UserStatusActive,
		Email: "legacycode@example.com", EmailVerified: true, TokenVersion: 3,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 旧版载荷：没有 token_version 字段。
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

// TestResetActivationRejectsAfterPasswordChange 覆盖「排队邮件在改密后才激活」。
//
// 令牌是送达时才创建的，改密时的撤销够不到它。载荷里记着入队时的
// TokenVersion，激活时在**用户行锁内**复核，不一致即作废。
func TestResetActivationRejectsAfterPasswordChange(t *testing.T) {
	svc := newTestServices(t, &config.Config{})

	u := &model.User{
		Username: "activationstale", Password: "not-used", Status: model.UserStatusActive,
		Email: "activationstale@example.com", EmailVerified: true, TokenVersion: 2,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	queuedVersion := 1 // 入队时的版本；之后用户改过密码，版本已变成 2
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
