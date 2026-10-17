package service

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「管理操作与运行时标记的配对生效」：
// 启用账号不得顺带放行超额用户、并发状态切换不得让内存与数据库背离、
// 清零撤销与采集提交不得交错、删除账号后遗留凭据不得继续工作。

// TestEnableUserKeepsExceededWhenRefreshFails 覆盖「启用失败时不放行超额用户」。
//
// 账号启用只是恢复登录资格，并不代表获得额外流量。刷新配额标记失败时
// 若把标记清成 false，超额用户会被放行到下一轮成功采集为止。
// 这里让刷新必然失败（去掉分组表，LoadUser 的 Preload 会报错），
// 同时用户表本身仍可更新——正是「状态改成功、刷新失败」的场景。
func TestEnableUserKeepsExceededWhenRefreshFails(t *testing.T) {
	svc := newTestServices(t, nil)

	// GroupID 非零：LoadUser 的 Preload 才会去查分组表，
	// 否则 GORM 会跳过这次查询，注不进「读取失败」。
	u := &model.User{Username: "enablefail", Password: "not-used",
		Status: model.UserStatusDisabled, GroupID: 1}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 前置：运行时认为该用户已超额。
	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)

	// 去掉分组表：用户表的 UPDATE 照常成功，随后的 LoadUser（Preload）
	// 必然失败，模拟「配额刷新读取失败」。
	if err := svc.DB.Migrator().DropTable(&model.Group{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	err := svc.AdminSetUserStatus(u.ID, model.UserStatusActive)
	if err == nil {
		t.Fatal("配额刷新失败必须如实报给管理员，不能报告启用成功")
	}
	if !svc.Runtime.IsQuotaExceeded(u.ID) {
		t.Fatal("刷新失败时不得清除原有超额标记：那等于给超额账号放行")
	}
	// 数据库里的状态确实已经改了——错误信息里必须点明这一点。
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.UserStatusActive {
		t.Fatalf("数据库状态应为 active，实际 %q", got.Status)
	}
}

// TestAdminSetUserStatusKeepsRuntimeInSync 覆盖「并发状态切换后内存与库一致」。
//
// 两笔相反的请求交错时，数据库与内存可能以不同顺序落地：库里是「已启用」，
// 内存却停在「已封禁」。按用户串行化之后，最终状态在两边必然一致。
func TestAdminSetUserStatusKeepsRuntimeInSync(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "toggle", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 多轮并发的「禁用 / 启用」对撞。
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled)
		}()
		go func() {
			defer wg.Done()
			_ = svc.AdminSetUserStatus(u.ID, model.UserStatusActive)
		}()
	}
	wg.Wait()

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	wantBlocked := got.Status != model.UserStatusActive
	if blocked := svc.Runtime.IsUserBlocked(u.ID); blocked != wantBlocked {
		t.Fatalf("内存封禁标记与数据库不一致：库状态 %q、内存封禁 %v", got.Status, blocked)
	}
}

// TestFlushTrafficRespectsRevokedMark 覆盖「撤销后不再跳过真实增量」。
//
// 分录：登记 → 撤销（清零写库失败）→ 采集落增量。撤销之后这一轮
// 必须正常入账，不能被一个已经作废的标记吞掉。
func TestFlushTrafficRespectsRevokedMark(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	gen := svc.Runtime.MarkTrafficResetPending(tun.UserID)
	svc.Runtime.UnmarkTrafficResetPending(tun.UserID, gen)

	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false,
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 500 {
		t.Fatalf("撤销后的增量必须正常入账，实际用量 %d（期望 500）", got)
	}
}

// TestFlushTrafficHoldsResetLock 覆盖「采集整轮持有清零协调锁」。
//
// 撤销必须等本轮提交完成才能生效：锁被占用期间 flushTraffic 不能开始，
// 从而不可能出现「校验通过 → 撤销 → 仍按标记跳过」的交错。
func TestFlushTrafficHoldsResetLock(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	unlock := svc.Runtime.lockTrafficReset()
	done := make(chan error, 1)
	go func() {
		done <- svc.flushTraffic(
			map[uint]*tunnelDelta{},
			map[uint]int64{tun.UserID: 100},
			nil, map[string]trafficPair{}, false,
		)
	}()

	select {
	case err := <-done:
		t.Fatalf("协调锁被占用时 flushTraffic 不应完成: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	unlock()
	if err := <-done; err != nil {
		t.Fatalf("释放锁后应正常落库: %v", err)
	}
}

// TestAdminResetHoldsResetLock 覆盖「成功清零也在协调区间内」。
//
// 只让撤销拿锁不够：采集可能已经取到不含该用户标记的快照，管理员随后
// 写零，采集再提交那份快照里的旧增量——清零后的用量又被加回。清零的
// 「登记 + 写库」必须和采集的「快照 → 提交」互斥。
func TestAdminResetHoldsResetLock(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "resetlock", Password: "not-used",
		Status: model.UserStatusActive, TrafficUsed: 4096}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	unlock := svc.Runtime.lockTrafficReset()
	done := make(chan error, 1)
	go func() { done <- svc.AdminResetUserTraffic(u.ID) }()

	select {
	case err := <-done:
		t.Fatalf("协调锁被采集占用时清零不应完成: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	unlock()
	if err := <-done; err != nil {
		t.Fatalf("释放锁后清零应成功: %v", err)
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.TrafficUsed != 0 {
		t.Fatalf("清零后用量应为 0，实际 %d", got.TrafficUsed)
	}
	// 标记仍在，等待下一轮采集消费（跳过清零前的旧增量）。
	if taken := svc.Runtime.takePendingTrafficResets(); len(taken) != 1 {
		t.Fatalf("清零后应留下待协调标记，实际 %v", taken)
	}
}

// TestDeleteAccountPurgesCredentials 覆盖「自助注销同样清理凭据与待发邮件」。
//
// 管理员删除已经清理了这些数据；自助注销曾经漏掉，注销后队列仍会投递
// 一封指向不存在账号的重置邮件，验证码也留在库里。
func TestDeleteAccountPurgesCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	hashed, err := auth.HashPassword("Passw0rd12345")
	if err != nil {
		t.Fatalf("生成密码失败: %v", err)
	}
	u := &model.User{Username: "selfpurge", Password: hashed,
		Status: model.UserStatusActive, Email: "selfpurge@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Create(&model.PasswordResetToken{
		UserID: u.ID, TokenHash: "self-token", ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Create(&model.EmailCode{
		Email: u.Email, Scene: "reset", CodeHash: "self-code",
		ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	mail := model.MailOutbox{
		To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
		Body: "code=123456", Payload: `{"user_id":1}`,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(&mail).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.DeleteAccount(u.ID, "Passw0rd12345"); err != nil {
		t.Fatalf("注销失败: %v", err)
	}

	var tokens, codes int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Model(&model.EmailCode{}).
		Where("email = ?", u.Email).Count(&codes).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 || codes != 0 {
		t.Fatalf("注销后不应留下令牌/验证码，实际 %d / %d 条", tokens, codes)
	}
	var got model.MailOutbox
	if err := svc.DB.First(&got, mail.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.MailFailed {
		t.Fatalf("待发邮件应作废，实际状态 %q", got.Status)
	}
	if got.Body != "" || got.Payload != "" {
		t.Fatal("作废时正文与参数（含明文凭据）必须清空")
	}
}

// TestAdminDeleteUserPurgesResetCredentials 覆盖「删除账号后替死凭据一并清理」。
//
// 留在库里的重置令牌与待发邮件会让用户点开链接后走到一个不存在的账号，
// 而删除账号应当让这些路径彻底失效。
func TestAdminDeleteUserPurgesResetCredentials(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "purged", Password: "not-used",
		Status: model.UserStatusActive, Email: "purged@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Create(&model.PasswordResetToken{
		UserID: u.ID, TokenHash: "purge-token", ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Create(&model.EmailCode{
		Email: u.Email, Scene: "reset", CodeHash: "purge-code",
		ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	mail := model.MailOutbox{
		To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
		Body: "code=123456", Payload: `{"user_id":1}`,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := svc.DB.Create(&mail).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("删除用户失败: %v", err)
	}

	var tokens int64
	if err := svc.DB.Model(&model.PasswordResetToken{}).
		Where("user_id = ?", u.ID).Count(&tokens).Error; err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("令牌应随账号一并删除，实际还剩 %d 条", tokens)
	}
	var codes int64
	if err := svc.DB.Model(&model.EmailCode{}).
		Where("email = ?", u.Email).Count(&codes).Error; err != nil {
		t.Fatal(err)
	}
	if codes != 0 {
		t.Fatalf("验证码应随账号一并删除，实际还剩 %d 条", codes)
	}
	var got model.MailOutbox
	if err := svc.DB.First(&got, mail.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.MailFailed {
		t.Fatalf("待发邮件应作废，实际状态 %q", got.Status)
	}
	if got.Body != "" || got.Payload != "" {
		t.Fatal("作废时正文与参数（含明文凭据）必须清空")
	}
}

// TestResetPasswordForDeletedUserIsInvalid 覆盖「账号已删时令牌不再报告成功」。
//
// 模拟升级前遗留的令牌：账号已被直接删除，令牌还在。重置必须返回
// 令牌无效且**不消费**令牌（事务回滚），而不是提交一个空的「重置成功」。
func TestResetPasswordForDeletedUserIsInvalid(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "vanished", Password: "not-used",
		Status: model.UserStatusActive, Email: "vanished@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	plain, hash, err := newResetToken()
	if err != nil {
		t.Fatal(err)
	}
	tok := model.PasswordResetToken{UserID: u.ID, TokenHash: hash,
		ExpireAt: time.Now().Add(time.Hour)}
	if err := svc.DB.Create(&tok).Error; err != nil {
		t.Fatal(err)
	}
	// 直接删用户行，留下令牌（模拟删除逻辑补全之前的历史数据）。
	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}

	err = svc.ResetPassword(plain, "newpassword123", "127.0.0.1")
	if !errors.Is(err, ErrResetTokenInvalid) {
		t.Fatalf("账号不存在时应返回令牌无效，实际 %v", err)
	}
	var after model.PasswordResetToken
	if err := svc.DB.First(&after, tok.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.UsedAt != nil {
		t.Fatal("失败的这次重置不应把令牌标记为已使用（事务应回滚）")
	}
}

// TestMailActionObsoleteForDeletedUser 覆盖「账号已删时凭据动作作废」。
//
// 邮件已入队、账号随后被删：激活时应识别出目标账号不存在，
// 按已办结处理（不重试、不落一条指向空账号的令牌）。
func TestMailActionObsoleteForDeletedUser(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "mailgone", Password: "not-used",
		Status: model.UserStatusActive, Email: "mailgone@example.com"}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	raw, err := json.Marshal(resetLinkPayload{UserID: u.ID, TokenHash: "gone-hash", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	row := model.MailOutbox{
		To: u.Email, Subject: "s", Kind: model.MailKindResetLink,
		Payload: string(raw), Status: model.MailDelivered,
		NextAt: time.Now().Add(-time.Second),
	}
	if err := svc.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Delete(&model.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}

	if err := svc.applyMailAction(row); !errors.Is(err, errMailActionObsolete) {
		t.Fatalf("账号已删时应返回「动作作废」，实际 %v", err)
	}

	// 走完整收尾：按已办结处理，不留下重试。
	svc.finishMailAction(row)
	var after model.MailOutbox
	if err := svc.DB.First(&after, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailSent {
		t.Fatalf("作废的动作应标为已办结，实际 %q（%s）", after.Status, after.LastErr)
	}
	if after.Payload != "" {
		t.Fatal("办结后参数（含摘要）必须清空")
	}
}
