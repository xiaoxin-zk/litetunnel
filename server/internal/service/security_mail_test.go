package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

func TestEmailCodeKeepsOldCodeWhenDeliveryFails(t *testing.T) {
	svc, fm := newMailTestServices(t)
	fm.setFail(true)

	const email = "keepold@example.com"
	old := model.EmailCode{
		Email: email, Scene: EmailSceneRegister,
		CodeHash: "old-hash", ExpireAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}
	if err := svc.DB.Create(&old).Error; err != nil {
		t.Fatalf("建旧验证码失败: %v", err)
	}

	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功（投递是后台的事）: %v", err)
	}

	for i := 0; i < mailMaxAttempts+1; i++ {
		deliverAll(svc)
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
	if out.Body != "" {
		t.Error("确定不再重发后应清空正文")
	}
	if out.Payload != "" {
		t.Error("确定不会激活后应清空参数")
	}
}

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

func TestMailOutboxSurvivesRestart(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "survive@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

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

func TestSendEmailCodeCooldownCountsOutbox(t *testing.T) {
	svc, _ := newMailTestServices(t)

	const email = "cooldown@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("首次发送应成功: %v", err)
	}
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); !errors.Is(err, ErrEmailCodeTooSoon) {
		t.Fatalf("短时间内重发应被冷却拦住，实际 %v", err)
	}
}

func TestInvalidEmailCodeSkipsBcrypt(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "bcryptskip@example.com"
	u := &model.User{
		Username: "bcryptskip", Password: "not-used",
		Email: email, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	sum := sha256.Sum256([]byte("123456"))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneReset,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	start := time.Now()
	if _, err := auth.HashPassword("NewPassw0rd!"); err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	baseline := time.Since(start)

	start = time.Now()
	err := svc.ResetPasswordByEmailCode(u.Username, "000000", "NewPassw0rd!", "127.0.0.1")
	wrongDur := time.Since(start)
	if err == nil {
		t.Fatal("错误的验证码应被拒绝")
	}

	if wrongDur > baseline/2 {
		t.Fatalf("验证码错误时不该做 bcrypt：耗时 %v，而一次哈希只要 %v",
			wrongDur.Round(time.Millisecond), baseline.Round(time.Millisecond))
	}
}

func TestEmailCodeCheckFailsWhenAttemptsCannotBeRecorded(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "countfail@example.com"
	sum := sha256.Sum256([]byte("123456"))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneReset,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	if err := svc.DB.Exec(
		`CREATE TRIGGER lt_email_codes_block_update BEFORE UPDATE ON lt_email_codes
		 BEGIN SELECT RAISE(ABORT, 'blocked for test'); END`).Error; err != nil {
		t.Fatalf("装触发器失败: %v", err)
	}

	_, err := svc.checkEmailCode(svc.DB, email, EmailSceneReset, "000000")
	if !errors.Is(err, ErrEmailCodeCheckFailed) {
		t.Fatalf("计数写不进去时必须报服务错误，实际 %v", err)
	}
	if errors.Is(err, ErrEmailCodeWrong) {
		t.Error("不能返回「验证码错误」：那等于让攻击者无限试码")
	}
}

func TestEmailCodeAttemptsNeverExceedLimit(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "attemptsrace@example.com"
	sum := sha256.Sum256([]byte("123456"))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneReset,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	const workers = 20
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.checkEmailCode(svc.DB, email, EmailSceneReset, "000000")
		}()
	}
	wg.Wait()

	var got model.EmailCode
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.Attempts != emailCodeMaxAttempts {
		t.Fatalf("%d 次并发错误尝试后计数应恰好停在上限 %d，实际 %d",
			workers, emailCodeMaxAttempts, got.Attempts)
	}
}

func TestConsumeEmailCodeRejectsExhaustedOrExpired(t *testing.T) {
	svc := newTestServices(t, nil)

	mk := func(name string, attempts int, expireAt time.Time) model.EmailCode {
		rec := model.EmailCode{
			Email: name + "@example.com", Scene: EmailSceneReset,
			CodeHash: "h", Attempts: attempts, ExpireAt: expireAt,
		}
		if err := svc.DB.Create(&rec).Error; err != nil {
			t.Fatalf("建验证码失败: %v", err)
		}
		return rec
	}

	exhausted := mk("exhausted", emailCodeMaxAttempts, time.Now().Add(10*time.Minute))
	expired := mk("expired", 0, time.Now().Add(-time.Minute))
	fresh := mk("fresh", 0, time.Now().Add(10*time.Minute))

	if err := svc.consumeEmailCode(svc.DB, exhausted.ID); !errors.Is(err, ErrEmailCodeWrong) {
		t.Errorf("已达尝试上限的验证码不该能被消费，实际 %v", err)
	}
	if err := svc.consumeEmailCode(svc.DB, expired.ID); !errors.Is(err, ErrEmailCodeWrong) {
		t.Errorf("已过期的验证码不该能被消费，实际 %v", err)
	}
	if err := svc.consumeEmailCode(svc.DB, fresh.ID); err != nil {
		t.Fatalf("正常验证码应能消费: %v", err)
	}
	if err := svc.consumeEmailCode(svc.DB, fresh.ID); !errors.Is(err, ErrEmailCodeWrong) {
		t.Errorf("同一个验证码不能被消费两次，实际 %v", err)
	}
}

func TestRegisterKeepsEmailCodeWhenInsertFails(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterEnabled:      "true",
		KeyRegisterRequireEmail: "true",
		KeyRegisterCaptcha:      "false",
	}); err != nil {
		t.Fatalf("设置注册开关失败: %v", err)
	}

	const email = "registerfail@example.com"
	const plain = "654321"
	sum := sha256.Sum256([]byte(plain))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneRegister,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	if err := svc.DB.Exec(
		`CREATE TRIGGER lt_users_block_insert BEFORE INSERT ON lt_users
		 BEGIN SELECT RAISE(ABORT, 'blocked for test'); END`).Error; err != nil {
		t.Fatalf("装触发器失败: %v", err)
	}

	_, err := svc.Register(RegisterInput{
		Username: "registerfail", Password: "Passw0rd123",
		Email: email, EmailCode: plain, AgreedTerms: true, IP: "127.0.0.1",
	})
	if err == nil {
		t.Fatal("写用户失败时注册应返回错误")
	}

	var got model.EmailCode
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.UsedAt != nil {
		t.Error("注册没成功时验证码不该被消费：否则用户只能重新收信")
	}

	if err := svc.DB.Exec(`DROP TRIGGER lt_users_block_insert`).Error; err != nil {
		t.Fatalf("删触发器失败: %v", err)
	}
	if _, err := svc.Register(RegisterInput{
		Username: "registerfail", Password: "Passw0rd123",
		Email: email, EmailCode: plain, AgreedTerms: true, IP: "127.0.0.1",
	}); err != nil {
		t.Fatalf("恢复后应能用同一个验证码完成注册: %v", err)
	}
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.UsedAt == nil {
		t.Error("注册成功后验证码必须被消费（一次性）")
	}
}

func TestResetByEmailCodeKeepsCodeWhenPasswordUpdateFails(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "resetcode@example.com"
	u := &model.User{
		Username: "resetcodework", Password: "not-used",
		Email: email, EmailVerified: true, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const plain = "123456"
	sum := sha256.Sum256([]byte(plain))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneReset,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	if err := svc.DB.Migrator().DropTable(&model.ClientSession{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	err := svc.ResetPasswordByEmailCode(u.Username, plain, "NewPassw0rd!", "127.0.0.1")
	if err == nil {
		t.Fatal("密码更新失败时应返回错误")
	}

	var got model.EmailCode
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.UsedAt != nil {
		t.Error("密码没改成时验证码不该被消费：否则用户只能等冷却后重新申请")
	}

	if err := svc.DB.AutoMigrate(&model.ClientSession{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}
	if err := svc.ResetPasswordByEmailCode(u.Username, plain, "NewPassw0rd!", "127.0.0.1"); err != nil {
		t.Fatalf("恢复后应能用同一个验证码完成重置: %v", err)
	}
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.UsedAt == nil {
		t.Error("成功重置后验证码必须被消费（一次性）")
	}

	if err := svc.ResetPasswordByEmailCode(u.Username, plain, "AnotherPassw0rd!", "127.0.0.1"); err == nil {
		t.Error("同一个验证码不能重复使用")
	}
}

func TestWrongEmailCodeStillCountsAttempts(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "attempts@example.com"
	u := &model.User{
		Username: "attemptsuser", Password: "not-used",
		Email: email, EmailVerified: true, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	sum := sha256.Sum256([]byte("123456"))
	rec := model.EmailCode{
		Email: email, Scene: EmailSceneReset,
		CodeHash: hex.EncodeToString(sum[:]),
		ExpireAt: time.Now().Add(10 * time.Minute),
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("建验证码失败: %v", err)
	}

	if err := svc.ResetPasswordByEmailCode(u.Username, "000000", "NewPassw0rd!", "127.0.0.1"); err == nil {
		t.Fatal("错误的验证码应被拒绝")
	}
	var got model.EmailCode
	if err := svc.DB.First(&got, rec.ID).Error; err != nil {
		t.Fatalf("读验证码失败: %v", err)
	}
	if got.Attempts != 1 {
		t.Fatalf("校验失败应累加次数（防暴力枚举），实际 %d", got.Attempts)
	}
}

func TestMailActionRetriedWithoutResending(t *testing.T) {
	svc, fm := newMailTestServices(t)

	const email = "retryaction@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	if err := svc.DB.Migrator().DropTable(&model.EmailCode{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	deliverAll(svc)

	if fm.sentCount() != 1 {
		t.Fatalf("应发出 1 封，实际 %d 封", fm.sentCount())
	}
	var row model.MailOutbox
	if err := svc.DB.Where("to_addr = ?", email).First(&row).Error; err != nil {
		t.Fatalf("读发件箱失败: %v", err)
	}
	if row.Status != model.MailDelivered {
		t.Fatalf("邮件已送达但激活失败时应停在 delivered（等待重试），实际 %q", row.Status)
	}
	if row.ActionAttempts == 0 {
		t.Error("应记录激活尝试次数")
	}
	if row.Attempts != 1 {
		t.Errorf("激活重试不该增加发送次数，实际 attempts=%d，期望 1", row.Attempts)
	}
	if row.Body != "" {
		t.Error("送达后应清空正文（含明文验证码）")
	}
	if row.Payload == "" {
		t.Error("激活完成之前不该清空参数")
	}

	if err := svc.DB.AutoMigrate(&model.EmailCode{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}
	if err := svc.DB.Model(&model.MailOutbox{}).Where("id = ?", row.ID).
		Update("next_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatalf("调整重试时间失败: %v", err)
	}
	deliverAll(svc)

	if fm.sentCount() != 1 {
		t.Fatalf("重试激活不该重发邮件，实际已发 %d 封", fm.sentCount())
	}

	if err := svc.DB.Where("to_addr = ?", email).First(&row).Error; err != nil {
		t.Fatalf("读发件箱失败: %v", err)
	}
	if row.Status != model.MailSent {
		t.Fatalf("激活成功后应标为 sent，实际 %q（错误: %s）", row.Status, row.LastErr)
	}
	if row.Payload != "" {
		t.Error("激活完成后应清空参数（里面是验证码摘要）")
	}
	if row.Attempts != 1 {
		t.Errorf("激活成功后发送次数仍应是 1，实际 %d", row.Attempts)
	}

	var n int64
	if err := svc.DB.Model(&model.EmailCode{}).Where("email = ?", email).
		Count(&n).Error; err != nil {
		t.Fatalf("统计验证码失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("激活后应有一条可用的验证码，实际 %d 条", n)
	}
}
