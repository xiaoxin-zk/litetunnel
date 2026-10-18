package service

import (
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

// TestPasswordChangeDropsClientSessions 覆盖「改密后 frpc 仍能继续连」。
//
// token_version 只让网页 JWT 失效；frpc 用的是 client_secret，不受它影响。
// 插件热路径又只查内存会话，所以数据库与内存两边都必须处理。
func TestPasswordChangeDropsClientSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	hashed, err := auth.HashPassword("OldPassw0rd!")
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	u := &model.User{Username: "pwchange", Password: hashed, Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-pw-1"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID, Online: true,
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	if err := svc.UpdatePassword(u.ID, "OldPassw0rd!", "NewPassw0rd!"); err != nil {
		t.Fatalf("改密失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Error("改密后内存会话必须被清掉：插件热路径只查它，留着就还会放行新连接")
	}
	var sess model.ClientSession
	if err := svc.DB.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if sess.Online {
		t.Error("改密后数据库会话应标记为离线")
	}
}

// TestAdminResetPasswordDropsClientSessions 覆盖管理员重置密码的同一问题。
func TestAdminResetPasswordDropsClientSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "adminreset", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-ar-1"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID, Online: true,
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	if err := svc.AdminResetUserPassword(u.ID, "ResetPassw0rd!"); err != nil {
		t.Fatalf("重置密码失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Error("管理员重置密码后内存会话必须被清掉")
	}
	var sess model.ClientSession
	if err := svc.DB.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if sess.Online {
		t.Error("管理员重置密码后数据库会话应标记为离线")
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

// TestAccessGuardIsUnknownUntilLoaded 覆盖「准入状态未知」不能当成「没超额」。
//
// 超额与禁用标记只在内存里，由后台采集维护；而采集在数据库不可用、
// frps 管理 API 不可达、采样基线读不出来时会**整轮跳过**。跳过期间内存里
// 什么标记都没有，而插件热路径把「查不到」当成「没超额」放行——控制面刚
// 启动、所有客户端同时重连的那段时间，超额与已禁用账号会被一并放进来。
// 所以状态必须可查询，且只有整表加载成功才算「已知」。
func TestAccessGuardIsUnknownUntilLoaded(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "quotaover", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Updates(map[string]any{"traffic_quota": 1, "traffic_used": 2}).Error; err != nil {
		t.Fatalf("设置配额失败: %v", err)
	}

	// 刚启动：谁都不知道。
	if svc.Runtime.AccessGuardReady() {
		t.Fatal("前置条件：新建的服务不该已经处于「准入状态已知」")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("前置条件：内存里不该有超额标记")
	}

	// 加载之后：如实反映库里的现状，并把状态翻成「已知」。
	if !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	if !svc.Runtime.AccessGuardReady() {
		t.Fatal("加载成功后必须标记为已知，否则插件会一直拒绝所有人")
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("已用 2 > 配额 1 的账号必须被标记，否则它仍能建隧道")
	}
}

// TestLoadAccessGuardKeepsUnknownOnDBError 覆盖加载失败时不能假装知道。
//
// 失败却置位，插件就会按「内存里没有 ⇒ 没超额」放行，准入控制等于关掉；
// 正确行为是保持未知、让插件显式拒绝，由采集协程重试到数据库恢复。
func TestLoadAccessGuardKeepsUnknownOnDBError(t *testing.T) {
	svc := newTestServices(t, nil)

	sqlDB, err := svc.DB.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	if svc.LoadAccessGuard() {
		t.Fatal("数据库不可用时不该报告加载成功")
	}
	if svc.Runtime.AccessGuardReady() {
		t.Fatal("加载失败后状态必须保持「未知」：置位等于按「谁都没超额」放行")
	}
}

// TestLoginFailureCountsOnlyCredentialGuesses 覆盖计数口径。
//
// 三个要点：
//  1. 只有真正的猜测（密码错、动态口令错）才算；
//  2. 成功一次就清零——判定的是「连续」失败，否则改对密码的正常用户
//     会被一直要求验证码；
//  3. 大小写是同一个账号，否则交替提交就能把计数摊薄。
func TestLoginFailureCountsOnlyCredentialGuesses(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyLoginCaptchaAfter: "2"}); err != nil {
		t.Fatalf("设置阈值失败: %v", err)
	}
	const account = "reset-user"

	fail := func(result string) {
		svc.RecordLogin(LoginAttempt{Kind: model.LoginKindUser, Username: account, Result: result})
	}

	// 1) 密码错 + 动态口令错，各一次 → 到阈值。
	fail(model.LoginResultBadCred)
	fail(model.LoginResultTOTPFail)
	if !svc.CaptchaRequired("login", account) {
		t.Fatal("两次凭据猜测之后应当要求验证码")
	}

	// 3) 大小写不同也必须是同一个账号。
	if !svc.CaptchaRequired("login", "ReSet-User") {
		t.Fatal("计数键必须规范化：换个大小写不能变成另一个账号")
	}

	// 2) 成功一次即清零。
	svc.RecordLogin(LoginAttempt{Kind: model.LoginKindUser, Username: account, Result: model.LoginResultSuccess})
	if svc.CaptchaRequired("login", account) {
		t.Fatal("成功登录后应清零：判定的是连续失败")
	}

	// 1) 「要求验证码」与「账号被禁用」都不是密码猜测，不该累计。
	for i := 0; i < 5; i++ {
		fail(model.LoginResultLocked)
		fail(model.LoginResultDisabled)
	}
	if svc.CaptchaRequired("login", account) {
		t.Fatal("locked / disabled 不是一次密码猜测，不该把账号推到阈值")
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

// TestResetPasswordByLinkDropsSessions 覆盖「邮件链接重置密码后旧 frpc 仍可建连」。
//
// 链接重置原先只把数据库会话标成离线，没有清本机内存会话；而插件热路径命中
// 内存会话后只看配额就放行，不会去读数据库——旧 frpc 于是还能继续建立新连接，
// 而「重置密码」的前提恰恰是账号可能已被他人控制。
func TestResetPasswordByLinkDropsSessions(t *testing.T) {
	svc := newTestServices(t, nil)

	hashed, err := auth.HashPassword("OldPassw0rd!")
	if err != nil {
		t.Fatalf("生成口令失败: %v", err)
	}
	u := &model.User{
		Username: "linkreset", Password: hashed, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-link-reset"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID,
		Online: true, LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建客户端会话失败: %v", err)
	}

	plain, hash, err := newResetToken()
	if err != nil {
		t.Fatalf("生成令牌失败: %v", err)
	}
	if err := svc.DB.Create(&model.PasswordResetToken{
		UserID: u.ID, TokenHash: hash, ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("写令牌失败: %v", err)
	}

	if err := svc.ResetPassword(plain, "NewPassw0rd!", "127.0.0.1"); err != nil {
		t.Fatalf("重置失败: %v", err)
	}

	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Fatal("链接重置密码后必须清掉本机内存会话，否则旧 frpc 仍能建立新连接")
	}
}

// TestSessionGuardRevokedWhenUserDeleted 覆盖「账号在别的实例被删」。
//
// 用户记录查询失败时若直接返回、保持原判，旧客户端会一直 Ping，本机就一直
// 留着这个会话，已有隧道继续接受新连接。这里要区分「用户不存在」（立即拒绝）
// 与「数据库暂时不可用」（保持原判）。
func TestSessionGuardRevokedWhenUserDeleted(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "deleteduser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-deleted"
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID,
		Online: true, LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建客户端会话失败: %v", err)
	}
	svc.PrimeSessionGuard(runID, u)
	if blocked, _, _ := svc.SessionGuard(runID); blocked {
		t.Fatal("前置条件：正常账号不该被拦")
	}

	// 模拟另一个实例删号（只动数据库，本机内存会话还在）。
	if err := svc.DB.Delete(&model.ClientSession{}, "user_id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}

	// 把快照时间拨回过去，触发一次刷新。
	svc.Runtime.mu.Lock()
	s := svc.Runtime.sessions[runID]
	s.GuardAt = time.Now().Add(-time.Minute)
	svc.Runtime.sessions[runID] = s
	svc.Runtime.mu.Unlock()

	svc.RefreshSessionGuard(runID)
	if blocked, _, ok := svc.SessionGuard(runID); !ok || !blocked {
		t.Fatal("账号已被删除时必须立即拒绝该会话，不能保持原判")
	}
}

// TestSessionGuardSharedByBothPaths 覆盖「代理注册与新连接各查各的」。
//
// 两条路径共用同一份会话快照，否则多副本下会出现「配额已放宽仍拒注册」
// 或「会话已撤销却注册成功、后续连接全被拒」这种自相矛盾的结果。
func TestSessionGuardSharedByBothPaths(t *testing.T) {
	svc := newTestServices(t, nil)

	const runID = "run-shared"
	svc.Runtime.RecordLogin(runID, 42, "shareduser")
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("快照未建立时应返回 ok=false，由调用方回落到本机标记")
	}

	svc.Runtime.SetSessionGuard(runID, true, true)
	blocked, exceeded, ok := svc.SessionGuard(runID)
	if !ok || !blocked || !exceeded {
		t.Fatalf("应读到会话快照：blocked=%v exceeded=%v ok=%v", blocked, exceeded, ok)
	}
}

// TestSessionGuardRefresh 覆盖「别的实例禁用账号后本实例继续放行」。
func TestSessionGuardRefresh(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "guardrefresh", Password: "not-used", Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-guard"
	// 真实流程里内存会话一定对应一条数据库会话（登录时写入）。
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID,
		Online: true, LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建客户端会话失败: %v", err)
	}
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
	svc.RefreshSessionGuard(runID)

	sess, ok := svc.Runtime.LookupSession(runID)
	if !ok {
		t.Fatal("会话应存在")
	}
	if sess.Blocked || sess.Exceeded {
		t.Fatalf("正常账号不该被拦：blocked=%v exceeded=%v", sess.Blocked, sess.Exceeded)
	}

	// 另一个实例把账号禁用（只写库，不碰本实例的内存标记）。
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusBanned).Error; err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	// 立刻刷新会被节流，这里把快照时间拨回过去模拟「一个 Ping 周期之后」。
	svc.Runtime.mu.Lock()
	s := svc.Runtime.sessions[runID]
	s.GuardAt = time.Now().Add(-time.Minute)
	svc.Runtime.sessions[runID] = s
	svc.Runtime.mu.Unlock()

	svc.RefreshSessionGuard(runID)

	sess, _ = svc.Runtime.LookupSession(runID)
	if !sess.Blocked {
		t.Fatal("账号在别的实例被禁用后，本实例的会话快照应在一个刷新周期内变为「已禁用」")
	}

	// 会话被撤销（重置密码/注销）同理：数据库里已离线，本机内存会话不能继续放行。
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusActive).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Model(&model.ClientSession{}).Where("run_id = ?", runID).
		Update("online", false).Error; err != nil {
		t.Fatal(err)
	}
	svc.Runtime.mu.Lock()
	s = svc.Runtime.sessions[runID]
	s.GuardAt = time.Now().Add(-time.Minute)
	svc.Runtime.sessions[runID] = s
	svc.Runtime.mu.Unlock()

	svc.RefreshSessionGuard(runID)
	sess, _ = svc.Runtime.LookupSession(runID)
	if !sess.Blocked {
		t.Fatal("数据库会话已撤销时，本机会话应在一个刷新周期内被拦下")
	}
}
