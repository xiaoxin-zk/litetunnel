package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// 这个文件守的都是同一类缺陷：**一处改了、另一处没跟上**。
//
// 单看任何一处代码都是对的，只有把数据库、运行态内存与采集循环串起来
// 才会暴露。所以这些用例都起真实的 sqlite 库与真实服务集合，
// 而不是把函数拆出来单独喂参数。

func newTestServices(t *testing.T, cfg *config.Config) *Services {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Env = "test"
	cfg.LogLevel = "warn"
	cfg.DBDriver = "sqlite"
	if cfg.DBDSN == "" {
		cfg.DBDSN = filepath.Join(t.TempDir(), "test.db")
	}
	if cfg.APIKeyEncKey == "" {
		cfg.APIKeyEncKey = "test-api-key-enc"
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先关连接再让 t.TempDir 清理：否则临时目录里的 sqlite 文件仍被占用，
	// 清理会失败（Windows 上尤其明显）。Cleanup 是后进先出，
	// 这里注册的比 TempDir 的晚，所以会先执行。
	t.Cleanup(func() { _ = sqlDB.Close() })
	return New(db, cfg)
}

func mustAdmin(t *testing.T, svc *Services, username, role string) *model.Admin {
	t.Helper()
	a, err := svc.CreateAdmin(AdminCreateInput{
		Username: username,
		Password: "AdminPass12345",
		Role:     role,
	})
	if err != nil {
		t.Fatalf("建管理员 %s 失败: %v", username, err)
	}
	return a
}

func loadAdmin(t *testing.T, svc *Services, id uint) model.Admin {
	t.Helper()
	var a model.Admin
	if err := svc.DB.First(&a, id).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	return a
}

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

// TestResetClientSecretRevokesSessions 覆盖「轮换凭据后已登录的 frpc 仍被放行」。
//
// 插件热路径（onNewUserConn，每次新建用户连接都经过）只查**内存**会话表，
// 命中后只校验配额就放行，根本不会读数据库。所以只把数据库会话置为离线
// 是不够的——内存里那份必须一起清。
func TestResetClientSecretRevokesSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "sessuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-revoke-1"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID, Online: true,
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); !ok {
		t.Fatal("前置条件不成立：内存会话应已登记")
	}

	if _, err := svc.ResetClientSecret(u); err != nil {
		t.Fatalf("重置客户端凭据失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Error("重置凭据后内存会话必须被清掉：插件热路径只查它，留着就还会放行新连接")
	}

	var sess model.ClientSession
	if err := svc.DB.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if sess.Online {
		t.Error("数据库会话应标记为离线（插件在内存未命中时会回落查它）")
	}
}

// TestDropUserSessionsOnlyDropsThatUser 确认清理不会误伤其他账号。
func TestDropUserSessionsOnlyDropsThatUser(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.RecordLogin("run-a1", 1, "a")
	svc.Runtime.RecordLogin("run-a2", 1, "a")
	svc.Runtime.RecordLogin("run-b1", 2, "b")

	if n := svc.Runtime.DropUserSessions(1); n != 2 {
		t.Fatalf("清理条数 = %d，期望 2", n)
	}
	if _, ok := svc.Runtime.LookupSession("run-b1"); !ok {
		t.Error("其他账号的会话不该被清掉")
	}
	if _, ok := svc.Runtime.LookupSession("run-a1"); ok {
		t.Error("目标账号的会话应被清空")
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
	go func() { done <- svc.AdminSetUserGroup(u.ID, g.ID, nil) }()

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

	if err := svc.AdminSetUserGroup(999999, g.ID, nil); err == nil {
		t.Fatal("用户不存在时必须报错，而不是静默成功")
	}
}

// TestDeleteAccountDropsRuntimeSessions 覆盖自助注销路径的会话清理。
//
// 管理员删除与密码重置都清了内存会话，自助注销曾经漏了：数据库里的会话行
// 随事务删除，但插件热路径查的是内存会话表，命中后只看配额就放行——
// 账号都注销了，已连接的 frpc 还能继续建新连接。
func TestDeleteAccountDropsRuntimeSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	hashed, err := auth.HashPassword("Passw0rd12345")
	if err != nil {
		t.Fatalf("生成密码失败: %v", err)
	}
	u := &model.User{Username: "selfdel", Password: hashed, Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-selfdel-1"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID, Online: true,
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	if err := svc.DeleteAccount(u.ID, "Passw0rd12345"); err != nil {
		t.Fatalf("注销失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Error("注销后内存会话必须被清掉：插件热路径只查它，留着就还会放行新连接")
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

// TestFirewallCloseFailureIsRetried 覆盖「收回失败被吞掉」。
//
// 隧道停用/删除时数据库已经改了、接口也返回成功，而防火墙操作可能因为
// helper 暂时不可达而失败。以前只写一行日志：规则一直开着，而启动时的
// 规则对齐只补开、不收回，所以没有任何地方会再尝试。
func TestFirewallCloseFailureIsRetried(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "fwretry", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20007,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用：helper 此刻是坏的，操作仍然成功（数据库已改），但端口要进重试队列。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20007/tcp 待收回" {
		t.Fatalf("收回失败应进入待重试队列，实际 %v", pending)
	}

	// helper 恢复后重试应当成功，并且真的调到了 helper。
	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待收回端口，实际 %d 个", n)
	}
	closed := helper.closedPorts()
	if len(closed) != 1 || closed[0] != "20007/tcp" {
		t.Fatalf("重试应真的收回端口，实际 %v", closed)
	}
	if len(svc.PendingFirewallOps()) != 0 {
		t.Error("成功后应从待重试队列移除")
	}
}

// enableTestMail 打开测试用的邮件配置，并确认 MailEnabled 成立。
func enableTestMail(t *testing.T, svc *Services) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeySMTPEnabled:  "true",
		KeySMTPHost:     "smtp.example.com",
		KeySMTPPort:     "587",
		KeySMTPUser:     "noreply@example.com",
		KeySMTPPassword: "secret",
		KeySMTPFrom:     "noreply@example.com",
	}); err != nil {
		t.Fatalf("设置邮件配置失败: %v", err)
	}
	if !svc.MailEnabled() {
		t.Fatal("前置条件：邮件应已启用")
	}
}

// fakeMailer 是可控的发信替身：用它把「投递成功」与「投递失败」变成确定性的。
type fakeMailer struct {
	mu   sync.Mutex
	fail bool
	sent []string
}

func (f *fakeMailer) Send(to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("smtp 不可用")
	}
	f.sent = append(f.sent, to)
	return nil
}

func (f *fakeMailer) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *fakeMailer) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// newMailTestServices 构造一个邮件已启用、发信器可替换的服务集合。
func newMailTestServices(t *testing.T) (*Services, *fakeMailer) {
	t.Helper()
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	fm := &fakeMailer{}
	svc.mailerOverride = fm
	return svc, fm
}

// deliverAll 驱动一次发件箱处理（正常路径由后台协程做，这里直接调用以便断言）。
func deliverAll(svc *Services) {
	svc.processMailOutbox(context.Background())
}

// TestEmailCodeNotActivatedBeforeDelivery 覆盖「信没送到、新码却已生效」。
//
// 验证码记录必须等邮件真的送达才创建：否则一旦这封信发不出去，
// 用户手上的旧码已经作废、新码又永远收不到——账号就此找不回来。
func TestEmailCodeNotActivatedBeforeDelivery(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "notyet@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	var n int64
	if err := svc.DB.Model(&model.EmailCode{}).Where("email = ?", email).
		Count(&n).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("送达之前不该创建验证码记录，实际 %d 条", n)
	}

	var out int64
	if err := svc.DB.Model(&model.MailOutbox{}).Where("to_addr = ?", email).
		Count(&out).Error; err != nil {
		t.Fatalf("统计发件箱失败: %v", err)
	}
	if out != 1 {
		t.Fatalf("应留下一封待发邮件，实际 %d 封", out)
	}
}

// TestEmailCodeKeepsOldCodeWhenDeliveryFails 覆盖「投递失败却把旧码作废了」。
//
// 信发不出去时，用户原有的验证码必须仍然可用——否则他每点一次
// 「重新发送」都会把上一次的码也作废掉，越试越回不去。
func TestEmailCodeKeepsOldCodeWhenDeliveryFails(t *testing.T) {
	svc, fm := newMailTestServices(t)
	fm.setFail(true)

	const email = "keepold@example.com"
	old := model.EmailCode{
		Email: email, Scene: EmailSceneRegister,
		CodeHash: "old-hash", ExpireAt: time.Now().Add(10 * time.Minute),
		// 越过 60 秒重发冷却，否则请求会被 ErrEmailCodeTooSoon 挡在前面。
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("建旧验证码失败: %v", err)
	}

	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功（投递是后台的事）: %v", err)
	}

	// 反复尝试直到重试次数耗尽：全程都不该动到旧码。
	for i := 0; i < mailMaxAttempts+1; i++ {
		deliverAll(svc)
		// 让退避到期，下一轮才会继续尝试。
		if err := svc.DB.Model(&model.MailOutbox{}).
			Where("to_addr = ?", email).
			Update("next_at", time.Now().Add(-time.Second)).Error; err != nil {
			t.Fatalf("调整重试时间失败: %v", err)
		}
	}

	var got model.EmailCode
	if err := svc.DB.First(&got, old.ID).Error; err != nil {
		t.Fatalf("读旧验证码失败: %v", err)
	}
	if got.UsedAt != nil {
		t.Error("投递失败不该作废旧验证码：用户会一个可用的码都没有")
	}

	var n int64
	if err := svc.DB.Model(&model.EmailCode{}).Where("email = ?", email).Count(&n).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if n != 1 {
		t.Errorf("投递失败不该产生新验证码，实际共 %d 条", n)
	}

	// 最终状态要能被看见，而不是永远挂着 pending。
	var out model.MailOutbox
	if err := svc.DB.Where("to_addr = ?", email).First(&out).Error; err != nil {
		t.Fatalf("读发件箱失败: %v", err)
	}
	if out.Status != model.MailFailed {
		t.Errorf("重试耗尽后应标为 failed（便于排查），实际 %q", out.Status)
	}
	if out.Attempts < mailMaxAttempts {
		t.Errorf("应记录重试次数，实际 %d", out.Attempts)
	}
}

// TestEmailCodeActivatesOnDelivery 覆盖送达之后的行为：新码生效、旧码作废。
//
// 两者必须是同一件事：只建新码不作废旧码，前面几封邮件里的码就都还能用，
// 等于扩大了攻击面。
func TestEmailCodeActivatesOnDelivery(t *testing.T) {
	svc, fm := newMailTestServices(t)

	const email = "activate@example.com"
	old := model.EmailCode{
		Email: email, Scene: EmailSceneRegister,
		CodeHash: "old-hash", ExpireAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("建旧验证码失败: %v", err)
	}

	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}
	deliverAll(svc)

	if fm.sentCount() != 1 {
		t.Fatalf("应发出一封信，实际 %d 封", fm.sentCount())
	}

	var got model.EmailCode
	if err := svc.DB.First(&got, old.ID).Error; err != nil {
		t.Fatalf("读旧验证码失败: %v", err)
	}
	if got.UsedAt == nil {
		t.Error("送达后旧码必须作废，否则多封邮件里的码同时可用")
	}

	var fresh model.EmailCode
	if err := svc.DB.Where("email = ? AND used_at IS NULL", email).
		Order("id desc").First(&fresh).Error; err != nil {
		t.Fatalf("应创建一条未使用的新验证码: %v", err)
	}
	if fresh.ID == old.ID {
		t.Fatal("留下的应当是刚送达的那条，而不是旧的")
	}

	var out model.MailOutbox
	if err := svc.DB.Where("to_addr = ?", email).First(&out).Error; err != nil {
		t.Fatalf("读发件箱失败: %v", err)
	}
	if out.Status != model.MailSent {
		t.Errorf("送达后应标为 sent，实际 %q", out.Status)
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

	if err := svc.RequestPasswordReset(u.Username, "127.0.0.1", "https://example.com"); err != nil {
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

// TestPendingCloseIsDroppedWhenPortIsReused 覆盖「旧任务关掉新隧道的端口」。
//
// 待办按端口保存，而端口会被复用：旧隧道删除后该端口分给了新隧道，
// 此时那条「收回 20001」的待办还在队列里——照着执行就会把新隧道的规则
// 一起关掉，用户看到的是「隧道莫名连不上」，而日志里只有一条「已补收回」。
func TestPendingCloseIsDroppedWhenPortIsReused(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "reuseuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 旧隧道：停用时收回失败，进入待办队列。
	old := &model.Tunnel{
		UserID: u.ID, Name: "old", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20011,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(old).Error; err != nil {
		t.Fatalf("建旧隧道失败: %v", err)
	}
	if err := svc.AdminSetTunnelStatus(old.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待收回记录，实际 %v", svc.PendingFirewallOps())
	}

	// 旧隧道被删除，端口 20011 分给了新隧道（且是启用状态）。
	if err := svc.AdminDeleteTunnel(old.ID); err != nil {
		t.Fatalf("删除旧隧道失败: %v", err)
	}
	fresh := &model.Tunnel{
		UserID: u.ID, Name: "new", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25566, RemotePort: 20011,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(fresh).Error; err != nil {
		t.Fatalf("建新隧道失败: %v", err)
	}

	// helper 恢复，重试——此时那条待办已经过时，必须作废而不是执行。
	helper.failCloses.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的待办应被作废，实际还剩 %d 条", n)
	}
	if got := helper.closedPorts(); len(got) != 0 {
		t.Fatalf("绝不能关掉已被新隧道复用的端口，实际关掉了 %v", got)
	}
}

// TestFirewallOpenFailureIsRetried 覆盖「放行失败没人重试」。
//
// 新建或启用隧道时会忽略 FirewallOpenPort 的错误，而防火墙协调器只在启动时
// 补开一次、之后只重试收回——helper 暂时不可用时，隧道一直处于启用状态但
// 端口没放行，只能靠人工重扫或重启服务。
func TestFirewallOpenFailureIsRetried(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failOpens.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "openretry", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20013,
		Status: model.TunnelStatusDisabled,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 启用：helper 坏的，数据库改了、放行失败，必须进入待办队列。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20013/tcp 待放行" {
		t.Fatalf("放行失败应进入待重试队列，实际 %v", pending)
	}

	// helper 恢复后重试应当真的放行。
	helper.failOpens.Store(false)
	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	opened := helper.openedPorts()
	if len(opened) != 1 || opened[0] != "20013/tcp" {
		t.Fatalf("重试应真的放行端口，实际 %v", opened)
	}
}

// TestPendingOpenIsDroppedWhenTunnelDisabled 覆盖反面：
// 待放行的端口若隧道又被停用，重试不能把端口开回来。
func TestPendingOpenIsDroppedWhenTunnelDisabled(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failOpens.Store(true)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "staleopen", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20015,
		Status: model.TunnelStatusDisabled,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待放行记录，实际 %v", svc.PendingFirewallOps())
	}

	// 用户又把它停用了（收回成功），此时那条待放行已经过时。
	helper.failOpens.Store(false)
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	helper.mu.Lock()
	helper.opened = nil
	helper.mu.Unlock()

	if n := svc.retryPendingFirewall(); n != 0 {
		t.Fatalf("过时的待放行应被作废，实际还剩 %d 条", n)
	}
	if got := helper.openedPorts(); len(got) != 0 {
		t.Fatalf("隧道已停用，绝不能把端口再开回来，实际 %v", got)
	}
}

// TestMailOutboxSurvivesRestart 覆盖「重启丢信」。
//
// 发信原先走内存 channel：进程一重启，队列里的信就没了。而验证码与重置链接
// 会在「信进队列」时就作废旧凭据——用户既收不到新凭据、旧凭据也失效，
// 账号彻底找不回来。所以待发的信必须落库。
func TestMailOutboxSurvivesRestart(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "survive@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	// 模拟重启：同一个数据库上新建一套 Services（内存态是空的），
	// 它启动后应当把遗留的信发出去。
	restarted := New(svc.DB, svc.Cfg)
	fm := &fakeMailer{}
	restarted.mailerOverride = fm

	deliverAll(restarted)

	if fm.sentCount() != 1 {
		t.Fatalf("重启后应把遗留的邮件发出去，实际发出 %d 封", fm.sentCount())
	}

	var n int64
	if err := restarted.DB.Model(&model.EmailCode{}).Where("email = ?", email).
		Count(&n).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("送达后应创建验证码记录，实际 %d 条", n)
	}
}

// TestSendEmailCodeCooldownCountsOutbox 覆盖「改了凭据创建时机后限流失效」。
//
// 限流原先数的是验证码记录，而记录现在要等送达才创建——继续数它的话，
// 反复触发发送就能绕过 60 秒冷却（每次都还没送达）。所以限流必须改数发件箱。
func TestSendEmailCodeCooldownCountsOutbox(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "cooldown@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("首次发送应成功: %v", err)
	}
	// 故意不投递：此时库里没有任何验证码记录。
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); !errors.Is(err, ErrEmailCodeTooSoon) {
		t.Fatalf("短时间内重发应被冷却拦住，实际 %v", err)
	}
}

// TestApplyPortIntentSkipsStaleClose 覆盖「立即路径不过时校验就动手」。
//
// 启停与删除都是「先改数据库、再动防火墙」，两步之间可能插进别的请求：
// 端口刚被新隧道占用，那条删除/停用的收回就会把新隧道的规则关掉。
// 动手前必须按当前状态确认意图仍然成立。
func TestApplyPortIntentSkipsStaleClose(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "staleclose", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20081,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 端口正被活跃隧道占用，此时「收回」的意图已经过时。
	acted, err := svc.applyPortIntent(20081, "tcp", false)
	if err != nil {
		t.Fatalf("不该有错误: %v", err)
	}
	if acted {
		t.Error("端口仍被活跃隧道占用，不该真的收回")
	}
	if got := helper.closedPorts(); len(got) != 0 {
		t.Fatalf("绝不能关掉活跃隧道的端口，实际关掉了 %v", got)
	}
	if got := svc.PendingFirewallOps(); len(got) != 0 {
		t.Errorf("过时的意图不该留下待办（否则会被反复重试），实际 %v", got)
	}
}

// TestApplyPortIntentSkipsStaleOpen 覆盖反面：没有隧道占用时不该放行。
//
// 对账拿的是某一刻的活跃隧道快照，逐条放行的过程中隧道可能已被停用或删除
// ——照着快照放行等于把一条已经不该开着的端口重新打开。
func TestApplyPortIntentSkipsStaleOpen(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	// 该端口没有任何隧道占用。
	acted, err := svc.applyPortIntent(20083, "tcp", true)
	if err != nil {
		t.Fatalf("不该有错误: %v", err)
	}
	if acted {
		t.Error("端口没有隧道占用，不该放行")
	}
	if got := helper.openedPorts(); len(got) != 0 {
		t.Fatalf("不该放行无归属的端口，实际 %v", got)
	}
}

// TestRetryKeepsNewIntentWrittenDuringOperation 覆盖「旧重试覆盖新意图」。
//
// 重试曾经在执行完 helper 操作后就释放端口锁，再回头更新/删除待办。这段间隙里
// 同一端口可能被写入**新意图**（刚停用的隧道又被启用），旧重试随后把新意图删掉
// ——那条真正需要的放行再也不会被重试，规则与数据库状态长期不一致。
//
// 现在「执行结果 + 待办状态提交」在同一段端口锁内，新意图只可能排在它之后写入。
func TestRetryKeepsNewIntentWrittenDuringOperation(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "intentrace", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20061,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用（helper 坏的）→ 产生「待收回」。
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if len(svc.PendingFirewallOps()) != 1 {
		t.Fatalf("前置条件：应有一条待收回，实际 %v", svc.PendingFirewallOps())
	}

	// 让重试的关端口卡在 helper 里，好在这期间插入新意图。
	helper.failCloses.Store(false)
	helper.failOpens.Store(true) // 新意图的放行会失败 → 必须留下待办
	helper.closeEntered = make(chan struct{}, 1)
	helper.closeGate = make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.retryPendingFirewall()
	}()

	select {
	case <-helper.closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("重试没有进入 helper 调用")
	}

	// 隧道被重新启用：产生新意图「待放行」。
	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("status", model.TunnelStatusActive).Error; err != nil {
		t.Fatalf("改状态失败: %v", err)
	}
	intentDone := make(chan struct{})
	go func() {
		defer close(intentDone)
		svc.applyPortIntent(20061, "tcp", true)
	}()

	close(helper.closeGate) // 放行重试继续
	<-done
	<-intentDone

	// 新意图必须还在：否则那条真正需要的放行不会再被重试。
	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20061/tcp 待放行" {
		t.Fatalf("新意图被旧重试覆盖或删除，实际 %v", pending)
	}
}

// TestTrafficBaselineSurvivesRestart 覆盖「控制面重启后重复计入当天流量」。
//
// 采样基线原先只在内存里。只重启控制面（frps 没重启、当天累计值还在）时，
// 第一次采集会把当天全部流量当成新增量记一遍——用户配额被凭空扣掉一大截，
// 统计也翻倍。滚动升级恰好就是这个形态。
func TestTrafficBaselineSurvivesRestart(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	u := &model.User{Username: "restarttraffic", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20071,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()

	// frps 今天已经累计了 5000 字节（在我们启动之前它就在跑了）。
	frps.total.Store(5000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5000 {
		t.Fatalf("首轮应记 5000，实际 %d", got)
	}

	// 模拟「只重启控制面、frps 没重启」：同一个库上新建一套 Services。
	restarted := New(svc.DB, cfg)
	restarted.Frps = NewFrpsClient(cfg)
	restarted.loadTrafficBaseline()

	// frps 的当天累计值没变，重启后的这一轮不该再记一遍。
	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5000 {
		t.Fatalf("重启后不该重复计入当天已有流量，实际 %d，期望 5000", got)
	}

	// 之后新增的流量仍要正常记上（基线恢复不能把采集算坏）。
	frps.total.Store(5200)
	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5200 {
		t.Fatalf("重启后新增流量应正常记入，实际 %d，期望 5200", got)
	}
}

// TestTrafficCollectorRestoresBaselineOnStart 覆盖上面那条修复的**接线**：
// 采集器必须在第一次采集之前恢复基线，否则修复形同没做。
func TestTrafficCollectorRestoresBaselineOnStart(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	if err := svc.DB.Create(&model.TrafficBaseline{
		ProxyName: "lt_u1.mc", Date: time.Now().Format("2006-01-02"),
		InBytes: 123, OutBytes: 456,
	}).Error; err != nil {
		t.Fatalf("写入基线失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartTrafficCollector(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		svc.Runtime.mu.RLock()
		cur, ok := svc.Runtime.lastStat["lt_u1.mc"]
		svc.Runtime.mu.RUnlock()
		if ok {
			if cur.in != 123 || cur.out != 456 {
				t.Fatalf("恢复的基线不对: %+v", cur)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("采集器启动时应先恢复采样基线，否则重启后会重复计入当天流量")
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

// TestDeleteTunnelQueuesFirewallClose 覆盖「用户删除单条隧道时忽略收回失败」。
//
// 这条路径原先直接调 FirewallClosePort 并丢掉返回值：helper 恰好不可用时，
// 记录已经删了、端口号再也查不回来，规则就永久留在宿主机防火墙上，
// 而且没有任何地方会再尝试收回。
func TestDeleteTunnelQueuesFirewallClose(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "deltun", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20021,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除隧道失败: %v", err)
	}

	pending := svc.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20021/tcp 待收回" {
		t.Fatalf("收回失败应进入待重试队列，实际 %v", pending)
	}
}

// TestPendingFirewallSurvivesRestart 覆盖「待办只存在内存里」。
//
// 关闭失败后若服务重启，那条意图就没了；而启动时的规则对齐**只补放行、
// 不回收**，于是旧规则会长期残留——端口对外开着，面板上那条隧道却早已
// 停用或删除，看不出任何异常。所以待办必须落库并在启动时恢复。
func TestPendingFirewallSurvivesRestart(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "restart", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20023,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	if err := svc.DeleteTunnel(u.ID, tun.ID); err != nil {
		t.Fatalf("删除隧道失败: %v", err)
	}

	var stored int64
	if err := svc.DB.Model(&model.FirewallPending{}).Where("port = ?", 20023).
		Count(&stored).Error; err != nil {
		t.Fatalf("统计待办失败: %v", err)
	}
	if stored != 1 {
		t.Fatalf("待办必须落库，实际库里 %d 条", stored)
	}

	// 模拟重启：同一个数据库上新建一套 Services（内存态是空的）。
	restarted := New(svc.DB, svc.Cfg)
	if len(restarted.PendingFirewallOps()) != 0 {
		t.Fatal("前置条件：新实例的内存队列应当是空的")
	}
	restarted.loadPendingFirewall()

	pending := restarted.PendingFirewallOps()
	if len(pending) != 1 || pending[0] != "20023/tcp 待收回" {
		t.Fatalf("重启后应恢复待办，实际 %v", pending)
	}

	// helper 恢复后，重启后的实例应当能把它真正收回。
	helper.failCloses.Store(false)
	if n := restarted.retryPendingFirewall(); n != 0 {
		t.Fatalf("重试后不应还有待办，实际 %d 条", n)
	}
	closed := helper.closedPorts()
	if len(closed) != 1 || closed[0] != "20023/tcp" {
		t.Fatalf("重启恢复的待办应真的收回端口，实际 %v", closed)
	}
}

// TestEnablingFirewallAtRuntimeAlignsRules 覆盖「运行中开启防火墙不生效」。
//
// 协调器原先在启动时读一次设置，关着就整个协程都不启动——管理员中途在面板
// 上打开防火墙后，既没有规则对齐、也没有 worker 重试待办，已有的活跃隧道
// 不会被放行，要重启服务才生效，而界面完全不提示。
func TestEnablingFirewallAtRuntimeAlignsRules(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	// 注意：这里**不**打开防火墙，模拟「启动时是关着的」。
	u := &model.User{Username: "runtimeon", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20031,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	svc.StartFirewallReconciler()
	// 协调器先睡 3 秒等 frps 与数据库就绪（见实现）。
	time.Sleep(3*time.Second + 300*time.Millisecond)

	// 运行中打开防火墙，并立刻唤醒协调器（设置页会这么做）。
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallAutoOpen:    "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("打开防火墙失败: %v", err)
	}
	svc.KickFirewall()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range helper.openedPorts() {
			if p == "20031/tcp" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("运行中打开防火墙后应对齐已有活跃隧道（放行 20031/tcp），实际已放行 %v",
		helper.openedPorts())
}

// TestRetryWaitsForPortLock 覆盖「校验意图与执行关闭之间的并发窗口」。
//
// 只校验不互斥的话仍有窗口：校验通过（此刻确实该关）→ 新隧道拿到这个端口
// 并放行 → 我们按旧意图把它关掉，新隧道刚建好就连不上。
// 竞态本身无法稳定复现，所以这里验证的是结构前提：重试会先取端口锁。
func TestRetryWaitsForPortLock(t *testing.T) {
	helper := newFakeFirewallHelper(t)
	helper.failCloses.Store(true)

	svc := newTestServices(t, nil)
	enableTestFirewall(t, svc, helper)

	u := &model.User{Username: "portlock", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20041,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	pl := svc.portLock(20041)
	pl.Lock() // 模拟「该端口的归属正在变化」

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.retryPendingFirewall()
	}()

	select {
	case <-done:
		t.Fatal("重试必须先取端口锁：否则校验与执行之间会插进新隧道的分配")
	case <-time.After(300 * time.Millisecond):
	}

	pl.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("释放端口锁后重试应立即继续")
	}
}

// TestCreateTunnelTakesPortLock 覆盖建隧道侧的结构前提。
//
// 取锁必须发生在**提交之前**：待办重试会先查数据库确认这个端口确实不该开着，
// 若此时创建事务尚未提交，它查不到这条新隧道就会认为可以关——随后我们提交、
// 放行，它紧接着把端口关掉。
func TestCreateTunnelTakesPortLock(t *testing.T) {
	// 指定端口必须落在配置的端口池范围内，所以这里给一个覆盖测试端口的区间。
	svc := newTestServices(t, &config.Config{PortRangeStart: 20000, PortRangeEnd: 20100})

	u := &model.User{Username: "createlock", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	g := &model.Group{
		Name: "锁测试组", MaxTunnels: 5, MaxPorts: 5,
		TrafficQuota: 1 << 30, BandwidthLimit: 1 << 20,
		AllowProtocols: "tcp", IsDefault: true,
	}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	u.GroupID = g.ID

	pl := svc.portLock(20043)
	pl.Lock()

	done := make(chan error, 1)
	go func() {
		_, err := svc.CreateTunnel(u, TunnelInput{
			Name: "mc", Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20043,
		})
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("建隧道应等待该端口的锁（实际立即返回，err=%v）", err)
	case <-time.After(300 * time.Millisecond):
	}

	pl.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("释放端口锁后建隧道应成功，实际 %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("释放端口锁后建隧道应立即继续")
	}
}

// enableTestFirewall 打开测试用的防火墙配置并指向假 helper。
func enableTestFirewall(t *testing.T, svc *Services, helper *fakeFirewallHelper) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallAutoOpen:    "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
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

// fakeFirewallHelper 冒充宿主机上的 lt-fw helper，记录收到的关端口请求。
//
// 面板自身没有任何防火墙写能力（全部转发给 helper），所以这里假的是 helper，
// 而不是「防火墙」——这样测到的就是真实那条转发链路。
type fakeFirewallHelper struct {
	*httptest.Server

	// failCloses / failOpens 为 true 时对应操作一律失败，用于模拟 helper 暂时不可用。
	failCloses atomic.Bool
	failOpens  atomic.Bool

	// closeEntered / closeGate 用于把「关端口」这一步卡住：
	// 进入处理时向 closeEntered 发信号，然后等 closeGate 才返回。
	// 用来在「重试执行到一半」时插入别的操作，验证临界区。
	closeEntered chan struct{}
	closeGate    chan struct{}

	mu     sync.Mutex
	opened []string
	closed []string
}

func newFakeFirewallHelper(t *testing.T) *fakeFirewallHelper {
	t.Helper()
	f := &fakeFirewallHelper{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"backend":"nft","available":true,"enabled":true}`))
		case "/ports/close":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.closeEntered != nil {
				select {
				case f.closeEntered <- struct{}{}:
				default:
				}
			}
			if f.closeGate != nil {
				<-f.closeGate
			}
			if f.failCloses.Load() {
				// 模拟 helper 暂时不可用：面板必须把这次失败记下来重试，
				// 而不是只写一行日志就当成关掉了。
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.closed = append(f.closed, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/ports/open":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.failOpens.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.opened = append(f.opened, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeFirewallHelper) closedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.closed))
	copy(out, f.closed)
	return out
}

func (f *fakeFirewallHelper) openedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.opened))
	copy(out, f.opened)
	return out
}

// TestAdminTunnelOpsTouchFirewall 覆盖「管理员操作不联动防火墙」。
//
// 用户侧的启停与删除都会开关端口，管理员侧却只改数据库：后台显示「已停用」，
// 主机防火墙上的规则仍然放行；删除后规则更是永久残留。
// 而启动时的规则对齐只负责「补开活跃端口」，不会清理这种残留。
func TestAdminTunnelOpsTouchFirewall(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "admintun", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20005,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 停用 → 收回端口
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusDisabled); err != nil {
		t.Fatalf("管理员停用失败: %v", err)
	}
	if got := helper.closedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员停用后应收回 20005/tcp，实际 %v", got)
	}

	// 启用 → 重新放行
	if err := svc.AdminSetTunnelStatus(tun.ID, model.TunnelStatusActive); err != nil {
		t.Fatalf("管理员启用失败: %v", err)
	}
	if got := helper.openedPorts(); len(got) != 1 || got[0] != "20005/tcp" {
		t.Fatalf("管理员启用后应重新放行 20005/tcp，实际 %v", got)
	}

	// 删除 → 收回端口
	if err := svc.AdminDeleteTunnel(tun.ID); err != nil {
		t.Fatalf("管理员删除失败: %v", err)
	}
	closed := helper.closedPorts()
	if len(closed) != 2 || closed[1] != "20005/tcp" {
		t.Fatalf("管理员删除后应再次收回 20005/tcp，实际 %v", closed)
	}
}

// TestRuntimeTouchAtIsPrunedWithSessions 覆盖心跳节流表只增不减。
//
// touchAt 按 runID 记录「上次落库时间」。客户端反复重连会产生大量
// runID，而这些条目既不会被会话清理带走，也不在 GC 的范围内——
// 长期运行的面板会一直攒着它们。
func TestRuntimeTouchAtIsPrunedWithSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	svc.Runtime.RecordLogin("run-a", 1, "a")
	svc.Runtime.RecordLogin("run-b", 2, "b")
	if !svc.Runtime.ShouldTouch("run-a", time.Minute) {
		t.Fatal("前置条件：首次心跳应允许落库")
	}
	if !svc.Runtime.ShouldTouch("run-b", time.Minute) {
		t.Fatal("前置条件：首次心跳应允许落库")
	}

	// 撤销某个用户的会话时，节流记录要一起清。
	svc.Runtime.DropUserSessions(1)
	if _, ok := svc.Runtime.touchAt["run-a"]; ok {
		t.Error("撤销会话后应一并清掉它的心跳节流记录")
	}
	if _, ok := svc.Runtime.touchAt["run-b"]; !ok {
		t.Error("不该动其他用户的节流记录")
	}

	// GC 清理过期会话时同样要清。
	//
	// 把时间戳回拨一小时再按 10 分钟窗口清理，而不是用 GC(0)：
	// GC(0) 的截止时刻就是「现在」，而它依赖两次 time.Now() 之间有可分辨的
	// 间隔——Windows 上时钟粒度不足时两次调用可能落在同一刻度，
	// Before 判为 false，测试就会随机失败（我自己写的用例踩过一次）。
	backdateSession(t, svc.Runtime, "run-b", time.Hour)
	svc.Runtime.GC(10 * time.Minute)

	if _, ok := svc.Runtime.sessions["run-b"]; ok {
		t.Fatal("前置条件：久未活动的会话应被回收")
	}
	if _, ok := svc.Runtime.touchAt["run-b"]; ok {
		t.Error("GC 回收会话时应一并清掉它的心跳节流记录")
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

// backdateSession 把某条会话的活跃时间往前拨，用于确定性地制造「久未活动」。
//
// 不用「GC(0)」这种把截止时刻设成现在的写法：它依赖两次 time.Now()
// 之间有可分辨的间隔，时钟粒度不足时会随机失败。
func backdateSession(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[runID]
	if !ok {
		t.Fatalf("前置条件不成立：会话 %s 不存在", runID)
	}
	s.LastSeen = s.LastSeen.Add(-by)
	r.sessions[runID] = s
}

// backdateTouchAt 把某条心跳节流记录的时间往前拨。
func backdateTouchAt(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.touchAt[runID]
	if !ok {
		t.Fatalf("前置条件不成立：节流记录 %s 不存在", runID)
	}
	r.touchAt[runID] = at.Add(-by)
}

// TestAdminDeleteUserClosesFirewallPorts 覆盖「删除用户后规则残留」。
//
// 单条隧道删除会收回端口，但批量删除用户时不会——隧道记录删掉后端口号
// 再也查不回来，规则就永久留在宿主机防火墙上。而启动时的规则对齐只负责
// 「放行已有的」，刻意不清理孤立规则（判断哪些是孤立的很容易误删）。
func TestAdminDeleteUserClosesFirewallPorts(t *testing.T) {
	helper := newFakeFirewallHelper(t)

	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}

	u := &model.User{Username: "fwuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	for i, port := range []int{20001, 20002} {
		tun := &model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("mc%d", i), Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: port,
			Status: model.TunnelStatusActive,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("删除用户失败: %v", err)
	}

	got := helper.closedPorts()
	if len(got) != 2 {
		t.Fatalf("应回收 2 个端口，实际 %v", got)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for _, want := range []string{"20001/tcp", "20002/tcp"} {
		if !seen[want] {
			t.Errorf("端口 %s 未被回收，实际 %v", want, got)
		}
	}
}

// fakeFrpsTraffic 是只上报一条代理的假 frps，累计流量可改。
type fakeFrpsTraffic struct {
	*httptest.Server
	total atomic.Int64
}

func newFakeFrpsTraffic(proxy string) *fakeFrpsTraffic {
	f := &fakeFrpsTraffic{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":%q,"status":{"phase":"online","todayTrafficIn":%d,"todayTrafficOut":0,"curConns":0}}]}}`,
			proxy, f.total.Load())
	}))
	return f
}

func tunnelTrafficUsed(t *testing.T, svc *Services, id uint) int64 {
	t.Helper()
	var tun model.Tunnel
	if err := svc.DB.First(&tun, id).Error; err != nil {
		t.Fatalf("读隧道失败: %v", err)
	}
	return tun.TrafficUsed
}

// TestCollectTrafficKeepsBaselineWhenFlushFails 覆盖「落库失败永久漏记流量」。
//
// 采样基线（Runtime.lastStat）如果先推进、再落库，事务失败时那一轮的增量
// 就永久丢了：下一轮从已经推进过的基线算增量，中间这段流量再也不会被记上。
// 用户看到的已用量比实际少（等于配额被悄悄放宽），统计也缺一块，
// 而日志里只有一行「落库失败」。
func TestCollectTrafficKeepsBaselineWhenFlushFails(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	u := &model.User{Username: "trafficuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()

	// 1) 正常一轮：1000 字节应落库
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("第一轮落库 = %d，期望 1000", got)
	}

	// 2) 制造落库失败：删掉按日统计表，flushTraffic 的事务会整体回滚
	if err := svc.DB.Migrator().DropTable(&model.TrafficDaily{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	frps.total.Store(2000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("落库失败的那一轮不该改动已用量（事务应整体回滚），实际 %d", got)
	}

	// 3) 恢复后下一轮必须把失败期间的增量一起补记
	if err := svc.DB.AutoMigrate(&model.TrafficDaily{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 2000 {
		t.Fatalf("恢复后应补记全部增量，实际 %d，期望 2000（少了说明采样基线被提前推进了）", got)
	}
}
