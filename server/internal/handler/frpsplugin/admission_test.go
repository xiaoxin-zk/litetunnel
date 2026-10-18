package frpsplugin

// 这一组守的是「账号刚被禁用、会话级准入快照又恰好未命中」这个窗口。
//
// 背景：代理注册与新连接两条路径都优先读**会话级**准入快照
// （service.SessionGuard，随 Ping 周期刷新）。快照未建立时（新会话还没
// Ping 过一次、控制面刚重启、会话刚被补登记）必须回落到本机内存标记，
// 而回落路径曾经只查了超额标记、漏了禁用标记：
//
//	禁用标记已置位（Runtime.SetUserBlocked）
//	→ SessionGuard 未命中（会话还没建立快照）
//	→ 只看 IsQuotaExceeded → 放行注册
//
// 于是「已禁用」的账号仍能把端口/域名绑到公网。注册那一刻 frps 就已经把
// 端口占上了，后续连接虽会被拒，但用户看到的是「隧道显示在线却连不上」，
// 而且没有任何后续事件会纠正这条已注册的代理。
//
// # 构造方式为什么是这样
//
// 用例刻意让数据库里的 users.status 保持 active，只置**运行时禁用标记**。
// 这不是为了绕开真实路径，而是因为只有这样才能命中被测的那条分支：
//
//   - 若把库里状态也改成 disabled，resolveUser 会在 authenticateByMeta /
//     identity 里先按「账号不是 active」拒掉，fallback 根本不会执行，
//     用例会因为一个无关的原因通过——测不到缺陷 5；
//   - 而「库已提交禁用、本机标记已置位」正是真实的竞态形态：禁用写入与
//     本次回调的 LoadUser 交错时，回调可能读到旧状态、却看到新标记。
//     标记是比库读更快的那一路信号，也正是 fallback 唯一能依赖的东西。
//
// 真实管理路径（AdminSetUserStatus）也有单独的断言，见
// TestNewProxyDeniesUserDisabledByAdmin。

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// newPluginTestHandler 起一套真实的 Services 并装好插件处理器。
//
// loadGuard 控制是否加载准入状态：false 用来复现「准入状态未知」的窗口，
// true 用来复现正常工作状态（否则所有回调都会被 denyUntilGuardReady 挡住，
// 用例就测不到它真正关心的那条判断）。
func newPluginTestHandler(t *testing.T, dbName string, loadGuard bool) (*service.Services, *Handler, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:            "test",
		LogLevel:       "warn",
		DBDriver:       "sqlite",
		DBDSN:          filepath.Join(t.TempDir(), dbName),
		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",
		// 与 plugin_session_test.go 保持同一套最小配置：字段少填会在
		// service.New 里的 SettingStore / CaptchaStore 初始化阶段暴露成
		// 难以定位的 panic，而不是一条清楚的失败信息。
		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",
	}
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先关连接再让 t.TempDir 清理（Windows 上 sqlite 文件被占用时删不掉）。
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := service.New(db, cfg)
	if loadGuard && !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	h := New(svc, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)
	return svc, h, r
}

// mustPluginUser 建一个账号并返回它。
func mustPluginUser(t *testing.T, svc *service.Services, username, secret string) *model.User {
	t.Helper()
	u := &model.User{
		Username:     username,
		Password:     "not-used-in-this-test",
		Status:       model.UserStatusActive,
		ClientSecret: secret,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	return u
}

// mustPluginTunnel 建一条可注册的 TCP 隧道。
func mustPluginTunnel(t *testing.T, svc *service.Services, u *model.User, name string, remotePort int) {
	t.Helper()
	tn := &model.Tunnel{
		UserID:     u.ID,
		Name:       name,
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: remotePort,
		Status:     model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tn).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
}

// mustPluginSession 登记一条**在线**的数据库会话 + 内存会话。
//
// 为什么需要它：resolveUser 的第一级回落是内存会话，只有先建出会话，
// 回调才能顺利通过身份解析、走到准入判断那一步。否则用例会被
// 「客户端未完成认证」提前拒掉，什么也没验到。
//
// 同时要保证这个会话**没有**准入快照（GuardAt 为零）：那正是缺陷 5
// 的触发条件（SessionGuard 返回 ok=false）。
func mustPluginSession(t *testing.T, svc *service.Services, u *model.User, runID string) {
	t.Helper()
	if err := svc.DB.Create(&model.ClientSession{
		UserID:     u.ID,
		Username:   u.Username,
		RunID:      runID,
		Online:     true,
		LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
}

// newProxyBody 拼一个 NewProxy 回调请求体（按 frp 的真实格式带用户前缀）。
//
// remotePort 必须与隧道配置一致：否则拒绝会发生在「远程端口与配置不一致」
// 那一步，用例就测不到准入判断——对照组会因此一直失败，而失败原因看起来
// 完全无关。
func newProxyBody(u *model.User, runID, tunnelName string, remotePort int) string {
	return fmt.Sprintf(
		`{"op":"NewProxy","content":{"user":{"user":%q,"run_id":%q},`+
			`"proxy_name":%q,"proxy_type":"tcp","remote_port":%d}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+"."+tunnelName, remotePort)
}

// newUserConnBody 拼一个 NewUserConn 回调请求体。
func newUserConnBody(u *model.User, runID, tunnelName string) string {
	return fmt.Sprintf(
		`{"op":"NewUserConn","content":{"user":{"user":%q,"run_id":%q},`+
			`"proxy_name":%q,"proxy_type":"tcp"}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+"."+tunnelName)
}

// markBlocked 走与真实管理路径相同的写法置上禁用标记。
//
// 顺序（先递增准入版本、再写标记）与 AdminSetUserStatus 完全一致：
// 版本推进是给在途读者「快照已过时」的信号，顺序反了会让读者拿着
// 旧版本号去读新标记。
func markBlocked(svc *service.Services, userID uint) {
	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetUserBlocked(userID, true)
}

// TestNewProxyFallbackDeniesBlockedUser 是缺陷 5 的核心用例。
//
// 构造：会话可解析（所以能走到准入判断）、SessionGuard 未命中
// （所以必然走 fallback）、本机禁用标记已置位。
//
// 这条断言在修复前会失败：fallback 只查超额标记，禁用标记被无视，
// 于是已禁用账号仍能注册新代理。
func TestNewProxyFallbackDeniesBlockedUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "blocked.db", true)
	u := mustPluginUser(t, svc, "blockeduser", "secret-blocked")
	mustPluginTunnel(t, svc, u, "mc", 21001)

	const runID = "run-blocked"
	mustPluginSession(t, svc, u, runID)

	// 前置条件：会话级快照确实未命中，否则用例走的是另一条分支，
	// 什么也没验到（这正是这条断言必须显式检查的原因）。
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}
	markBlocked(svc, u.ID)
	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：禁用标记必须已置位")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21001)))
	if !res.Reject {
		t.Fatal("账号已被禁用、会话快照未命中时，fallback 路径必须拒绝注册（缺陷 5）")
	}
}

// TestNewProxyFallbackDeniesExceededUser 守反面的一半：
//
// 修复时把禁用标记加了进来，但容易顺手把超额判断挪走或提前 return，
// 于是「超额账号仍能注册」——那会把配额断流从注册这一刻就废掉。
func TestNewProxyFallbackDeniesExceededUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "exceeded.db", true)
	u := mustPluginUser(t, svc, "exceededuser", "secret-exceeded")
	mustPluginTunnel(t, svc, u, "mc", 21002)

	const runID = "run-exceeded"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}

	// 只置超额标记、不动禁用标记：确保拒绝原因确实来自超额。
	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)
	if svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：本用例只应触发超额，不该同时是禁用状态")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21002)))
	if !res.Reject {
		t.Fatal("超额账号在 fallback 路径上必须拒绝注册")
	}
}

// TestNewProxyFallbackAllowsActiveUser 是必须存在的对照组。
//
// 少了它，「一律拒绝注册」也能让上面两条用例通过——而那会把所有正常用户
// 的隧道全部拦住。这条用例同时要求 fallback 路径在账号正常时确实放行。
func TestNewProxyFallbackAllowsActiveUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "active.db", true)
	u := mustPluginUser(t, svc, "activeuser", "secret-active")
	mustPluginTunnel(t, svc, u, "mc", 21003)

	const runID = "run-active"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21003)))
	if res.Reject {
		t.Fatalf("正常账号在 fallback 路径上必须放行，实际被拒（%s）", res.RejectReason)
	}
}

// TestNewProxyDeniesUserDisabledByAdmin 守真实管理路径。
//
// 与上面几条不同，这里走完整的 AdminSetUserStatus：库里状态变成 disabled，
// 会话被撤销。此时拒绝可能发生在身份解析阶段（账号不是 active）而不是
// 准入判断阶段——两种都算正确，关键是**必须拒绝**。
//
// 保留它的理由：上面那些用例为了命中 fallback 刻意只置标记，容易被误读成
// 「只有标记才拦得住」。这条证明真实禁用路径同样是关的。
func TestNewProxyDeniesUserDisabledByAdmin(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "admin-disabled.db", true)
	u := mustPluginUser(t, svc, "adminblocked", "secret-admin")
	mustPluginTunnel(t, svc, u, "mc", 21005)

	const runID = "run-admin-blocked"
	mustPluginSession(t, svc, u, runID)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用账号失败: %v", err)
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21005)))
	if !res.Reject {
		t.Fatal("管理员禁用之后必须拒绝注册新代理")
	}
}

// TestLocalAdmissionReportsUnready 守「准入状态未知时读不出可信判定」。
//
// 两个标记都只在整表加载成功后才有意义。整表没加载时 map 是空的，
// 「查不到」与「没禁用」在数据结构上完全一样——这时候必须返回 ok=false，
// 让调用方按拒绝处理，而不是把「空表」当成「一切正常」。
func TestLocalAdmissionReportsUnready(t *testing.T) {
	svc, h, _ := newPluginTestHandler(t, "unready.db", false)
	u := mustPluginUser(t, svc, "unreadyuser", "secret-unready")

	if svc.Runtime.AccessGuardReady() {
		t.Fatal("前置条件：没有加载过准入状态，不该已经是「已知」")
	}
	if _, _, ok := h.localAdmission(u.ID); ok {
		t.Fatal("准入状态未加载时必须报告「无法判定」，不能返回一份空表算出来的正常状态")
	}
}

// TestLocalAdmissionReadsStableSnapshot 守「版本稳定时才返回判定」。
//
// 稳定情况下一次就读到（ok=true 且值正确），这是 fallback 用例的前提：
// 不能因为加了版本比对就把正常路径也判成「不确定」，否则所有注册都会被拒。
func TestLocalAdmissionReadsStableSnapshot(t *testing.T) {
	svc, h, _ := newPluginTestHandler(t, "stable.db", true)
	u := mustPluginUser(t, svc, "stableuser", "secret-stable")

	blocked, exceeded, ok := h.localAdmission(u.ID)
	if !ok {
		t.Fatal("准入版本稳定时必须能读到可信判定")
	}
	if blocked || exceeded {
		t.Fatalf("正常账号不该被判定为禁用/超额（blocked=%v exceeded=%v）", blocked, exceeded)
	}

	markBlocked(svc, u.ID)
	blocked, exceeded, ok = h.localAdmission(u.ID)
	if !ok {
		t.Fatal("准入版本稳定时必须能读到可信判定")
	}
	if !blocked || exceeded {
		t.Fatalf("禁用后应只报告 blocked（blocked=%v exceeded=%v）", blocked, exceeded)
	}
}

// TestNewUserConnFallbackDeniesBlockedUser 覆盖另一处同类缺口。
//
// onNewUserConn 是每次新建连接都经过的实时拦截点，它的 fallback 分支
// （会话快照未命中）原先同样只查超额、漏了禁用。代价比代理注册更大：
// 漏放一条连接就是一条真正在传数据的数据流。
func TestNewUserConnFallbackDeniesBlockedUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "connblocked.db", true)
	u := mustPluginUser(t, svc, "connblocked", "secret-conn")
	mustPluginTunnel(t, svc, u, "mc", 21004)

	const runID = "run-conn-blocked"
	mustPluginSession(t, svc, u, runID)

	// 只置本机禁用标记、**不**碰会话快照：这样 EnsureSessionOnline 通过，
	// 但 SessionGuard 未命中，代码必然落到 fallback 分支——正是要测的那条。
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该会话不该已经建立准入快照")
	}
	markBlocked(svc, u.ID)

	res := decodeResponse(t, postPlugin(t, r, newUserConnBody(u, runID, "mc")))
	if !res.Reject {
		t.Fatal("账号已被禁用、会话快照未命中时，NewUserConn 的 fallback 路径必须拒绝新建连接")
	}
}

// TestNewUserConnFallbackAllowsActiveUser 是对照组：正常账号必须能连。
//
// 与 NewProxy 的同名对照组理由相同——少了它，把 fallback 改成一律拒绝
// 也能让上面那条通过，而那会让所有正常联机断掉。
func TestNewUserConnFallbackAllowsActiveUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "connactive.db", true)
	u := mustPluginUser(t, svc, "connactive", "secret-conn-active")
	mustPluginTunnel(t, svc, u, "mc", 21006)

	const runID = "run-conn-active"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该会话不该已经建立准入快照")
	}

	res := decodeResponse(t, postPlugin(t, r, newUserConnBody(u, runID, "mc")))
	if res.Reject {
		t.Fatalf("正常账号（快照未命中）必须放行新建连接，实际被拒（%s）", res.RejectReason)
	}
}
