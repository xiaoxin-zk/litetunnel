package service

import (
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

	if svc.Runtime.AccessGuardReady() {
		t.Fatal("前置条件：新建的服务不该已经处于「准入状态已知」")
	}
	if svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("前置条件：内存里不该有超额标记")
	}

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

func TestLoginFailureCountsOnlyCredentialGuesses(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyLoginCaptchaAfter: "2"}); err != nil {
		t.Fatalf("设置阈值失败: %v", err)
	}
	const account = "reset-user"

	fail := func(result string) {
		svc.RecordLogin(LoginAttempt{Kind: model.LoginKindUser, Username: account, Result: result})
	}

	fail(model.LoginResultBadCred)
	fail(model.LoginResultTOTPFail)
	if !svc.CaptchaRequired("login", account) {
		t.Fatal("两次凭据猜测之后应当要求验证码")
	}

	if !svc.CaptchaRequired("login", "ReSet-User") {
		t.Fatal("计数键必须规范化：换个大小写不能变成另一个账号")
	}

	svc.RecordLogin(LoginAttempt{Kind: model.LoginKindUser, Username: account, Result: model.LoginResultSuccess})
	if svc.CaptchaRequired("login", account) {
		t.Fatal("成功登录后应清零：判定的是连续失败")
	}

	for i := 0; i < 5; i++ {
		fail(model.LoginResultLocked)
		fail(model.LoginResultDisabled)
	}
	if svc.CaptchaRequired("login", account) {
		t.Fatal("locked / disabled 不是一次密码猜测，不该把账号推到阈值")
	}
}

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

	svc.Runtime.DropUserSessions(1)
	if _, ok := svc.Runtime.touchAt["run-a"]; ok {
		t.Error("撤销会话后应一并清掉它的心跳节流记录")
	}
	if _, ok := svc.Runtime.touchAt["run-b"]; !ok {
		t.Error("不该动其他用户的节流记录")
	}

	backdateSession(t, svc.Runtime, "run-b", time.Hour)
	svc.Runtime.GC(10 * time.Minute)

	if _, ok := svc.Runtime.sessions["run-b"]; ok {
		t.Fatal("前置条件：久未活动的会话应被回收")
	}
	if _, ok := svc.Runtime.touchAt["run-b"]; ok {
		t.Error("GC 回收会话时应一并清掉它的心跳节流记录")
	}
}

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

	if err := svc.DB.Delete(&model.ClientSession{}, "user_id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}

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

func TestSessionGuardRefresh(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{
		Username: "guardrefresh", Password: "not-used", Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const runID = "run-guard"
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

	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).
		Update("status", model.UserStatusBanned).Error; err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
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
