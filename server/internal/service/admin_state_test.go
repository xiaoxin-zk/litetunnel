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

func TestAdminSetUserGroupClearsExpireAt(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "clear-expire", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}
	future := time.Now().AddDate(0, 1, 0)
	u := &model.User{
		Username: "clearexpire", Password: "not-used", Status: model.UserStatusActive,
		GroupID: g.ID, GroupExpireAt: &future,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	if err := svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{Set: true, Value: nil}); err != nil {
		t.Fatalf("清空有效期失败: %v", err)
	}
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupExpireAt != nil {
		t.Fatalf("显式 null 必须清除到期时间，实际仍是 %v", got.GroupExpireAt)
	}

	if err := svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{Set: true, Value: &future}); err != nil {
		t.Fatal(err)
	}
	if err := svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupExpireAt == nil {
		t.Fatal("字段缺失时不该改动到期时间")
	}

	if err := svc.AdminSetUserGroup(u.ID, g.ID, GroupExpiry{Set: true, Value: nil}); err != nil {
		t.Fatal(err)
	}
	svc.refreshGuardDue()
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.GroupID != g.ID {
		t.Fatalf("没有到期时间的用户不该被迁回默认分组，实际 group_id=%d", got.GroupID)
	}
}

func TestEnableUserKeepsExceededWhenRefreshFails(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "enablefail", Password: "not-used",
		Status: model.UserStatusDisabled, GroupID: 1}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)

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
	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.UserStatusActive {
		t.Fatalf("数据库状态应为 active，实际 %q", got.Status)
	}
}

func TestAdminSetUserStatusKeepsRuntimeInSync(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "toggle", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

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

func TestFlushTrafficRespectsRevokedMark(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	gen := svc.Runtime.MarkTrafficResetPending(tun.UserID)
	svc.Runtime.UnmarkTrafficResetPending(tun.UserID, gen)

	if err := svc.flushTraffic(
		map[uint]*tunnelDelta{},
		map[uint]int64{tun.UserID: 500},
		nil, map[string]trafficPair{}, false, trafficFence{},
	); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, tun.UserID); got != 500 {
		t.Fatalf("撤销后的增量必须正常入账，实际用量 %d（期望 500）", got)
	}
}

func TestFlushTrafficHoldsResetLock(t *testing.T) {
	svc, _, tun := newEditTestTunnel(t)

	unlock := svc.Runtime.lockTrafficReset()
	done := make(chan error, 1)
	go func() {
		done <- svc.flushTraffic(
			map[uint]*tunnelDelta{},
			map[uint]int64{tun.UserID: 100},
			nil, map[string]trafficPair{}, false, trafficFence{},
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
	if taken := svc.Runtime.takePendingTrafficResets(); len(taken) != 1 {
		t.Fatalf("清零后应留下待协调标记，实际 %v", taken)
	}
}

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

	token := claimForTest(t, svc, row)
	if err := svc.applyMailAction(row, token); !errors.Is(err, errMailActionObsolete) {
		t.Fatalf("账号已删时应返回「动作作废」，实际 %v", err)
	}

	svc.finishMailAction(row, token)
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
