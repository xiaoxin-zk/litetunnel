package service

import (
	"context"
	"encoding/json"
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

	mu     sync.Mutex
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
			f.mu.Lock()
			f.closed = append(f.closed, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/ports/open":
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
