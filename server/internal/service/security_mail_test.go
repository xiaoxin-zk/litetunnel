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
	// 不会重发了，正文（含明文验证码）就该立刻抹掉，而不是等记录过期——
	// 数据库备份或只读泄露期间，留在库里的明文凭据仍然可用。
	if out.Body != "" {
		t.Error("确定不再重发后应清空正文")
	}
	if out.Payload != "" {
		t.Error("确定不会激活后应清空参数")
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

// TestInvalidEmailCodeSkipsBcrypt 覆盖「无效验证码也触发 bcrypt」。
//
// preparePasswordReset 里的 bcrypt 是刻意设计成慢的（防离线爆破）。若放在
// 校验验证码之前，任何一个错误验证码的请求都会消耗这段 CPU——接口虽有按 IP
// 限流，但分布式来源仍能把它放大成 CPU 耗尽。
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

	// 先量一次真实 bcrypt 的耗时作为基线。
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

	// 用**比值**而不是绝对阈值：CI 负载高时两边一起变慢，比值仍然成立。
	if wrongDur > baseline/2 {
		t.Fatalf("验证码错误时不该做 bcrypt：耗时 %v，而一次哈希只要 %v",
			wrongDur.Round(time.Millisecond), baseline.Round(time.Millisecond))
	}
}

// TestEmailCodeCheckFailsWhenAttemptsCannotBeRecorded 覆盖
// 「计数写库失败仍按普通验证码错误返回」。
//
// 那样的话只要让写库持续失败（打满连接池、磁盘写满……），攻击者就能无限次
// 猜码——每次失败都不计数，上限永远不会到。必须拒绝继续校验并如实报服务错误。
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

	// 让「记录失败次数」必然失败：给验证码表装一个拒绝更新的触发器。
	// 读仍然正常，正是要模拟的场景（读得到、写不进）。
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

// TestEmailCodeAttemptsNeverExceedLimit 覆盖「失败计数不是原子的」。
//
// 「先读上限、再无条件 +1」在并发下会漏：多个请求同时读到「还没到上限」的
// 旧值，各自继续校验，同一个 6 位码就能被猜超过规定的次数。
// 带条件的自增由数据库保证只有一次能生效，计数最终**恰好**停在上限。
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

// TestConsumeEmailCodeRejectsExhaustedOrExpired 覆盖消费时的条件校验。
//
// 校验与消费之间可能插进别的请求（并发猜测、或恰好跨过过期时刻），
// 只按 id 更新会把这些检查绕过去——一个已经该作废的验证码仍然能被用掉。
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

// TestRegisterKeepsEmailCodeWhenInsertFails 覆盖「注册没成功、验证码却已失效」。
//
// 消费验证码与写入用户如果分属两步，写库失败（或并发注册撞唯一索引）时，
// 用户得重新收信才能再试一次。
func TestRegisterKeepsEmailCodeWhenInsertFails(t *testing.T) {
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyRegisterEnabled:      "true",
		KeyRegisterRequireEmail: "true",
		// 人机验证默认是开的，这里关掉：本用例只关心验证码与写用户的先后。
		KeyRegisterCaptcha: "false",
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

	// 制造「写用户失败」：给用户表装一个拒绝插入的触发器。
	// 比「并发撞唯一索引」更确定，走的仍是真实注册路径。
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

	// 去掉触发器后重试：同一个验证码应当仍然可用。
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

// TestResetByEmailCodeKeepsCodeWhenPasswordUpdateFails 覆盖
// 「验证码被消费了、密码却没改成」。
//
// 消费验证码与更新密码如果分属两个事务，后者失败时会留下这个状态：
// 用户手里的码已经失效、密码还是旧的，只能等冷却后重新申请。
// 放进同一事务后，失败会一并回滚，验证码仍然可用。
func TestResetByEmailCodeKeepsCodeWhenPasswordUpdateFails(t *testing.T) {
	svc := newTestServices(t, nil)

	const email = "resetcode@example.com"
	u := &model.User{
		Username: "resetcodework", Password: "not-used",
		// 已验证：找回密码只认已验证的邮箱（未验证的地址从没证明过归属）。
		Email: email, EmailVerified: true, Status: model.UserStatusActive,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 造一个已知明文的验证码（存的是 SHA-256 摘要）。
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

	// 制造「密码更新失败」：删掉客户端会话表，事务里的 revokeClientSessionsTx 会失败。
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

	// 恢复后重试：同一个验证码应当仍然可用。
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

	// 已用过的码不能再被使用。
	if err := svc.ResetPasswordByEmailCode(u.Username, plain, "AnotherPassw0rd!", "127.0.0.1"); err == nil {
		t.Error("同一个验证码不能重复使用")
	}
}

// TestWrongEmailCodeStillCountsAttempts 覆盖反面：校验失败的计数不能被回滚掉。
//
// 失败次数是防 6 位码被暴力枚举的关键，必须在校验失败后立即生效；
// 如果把它塞进「消费 + 改密」那个事务里，事务一回滚计数就没了。
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

	// 故意用错码：失败次数必须被记下。
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

// TestMailActionRetriedWithoutResending 覆盖「激活失败被永久标为失败」。
//
// 邮件已经送达、用户手里有验证码，此时数据库瞬时故障让激活失败。若把两者绑成
// 一步，整封邮件会被标成 failed 而不再重试——用户拿着一个库里不存在的码，
// 谁也救不回来。所以「已送达」与「凭据已生效」必须能分别重试，且**不重发邮件**。
func TestMailActionRetriedWithoutResending(t *testing.T) {
	svc, fm := newMailTestServices(t)

	const email = "retryaction@example.com"
	if err := svc.SendEmailCode(email, EmailSceneRegister, "127.0.0.1"); err != nil {
		t.Fatalf("入队应成功: %v", err)
	}

	// 制造「激活失败」：把验证码表删掉，激活事务必然失败。
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
	// 激活重试**不是**发送尝试：发送次数必须还是 1。
	// 写回 row.Attempts + 1 的话，每轮激活重试都会把它多加一次，审计数据就废了。
	if row.Attempts != 1 {
		t.Errorf("激活重试不该增加发送次数，实际 attempts=%d，期望 1", row.Attempts)
	}
	// 正文在送达那一刻就该清掉（不会重发，留着只是把明文验证码多放一段时间）。
	if row.Body != "" {
		t.Error("送达后应清空正文（含明文验证码）")
	}
	// 参数要留着——激活还要用。
	if row.Payload == "" {
		t.Error("激活完成之前不该清空参数")
	}

	// 数据库恢复后重试：应当只补做激活，不重发邮件。
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
