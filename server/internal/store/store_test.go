package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := &config.Config{
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "store.db"),
	}
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先关连接再让 t.TempDir 清理（Windows 上文件仍被占用会清理失败）。
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// TestMailIDIsUniquePerCredential 覆盖「一封邮件只能激活出一条凭据」。
//
// 多实例并发激活同一封邮件时，两边的「已激活」检查可能都落空，各插一条相同
// 验证码；而校验只消费命中的那一条，另一条仍然可用——一次性语义就没了。
// 代码里的领取已经避免这种并发，唯一索引是最后一道保险。
func TestMailIDIsUniquePerCredential(t *testing.T) {
	db := newTestDB(t)

	first := &model.EmailCode{
		Email: "dup@example.com", Scene: "reset", CodeHash: "h1",
		ExpireAt: time.Now().Add(time.Hour), MailID: 7,
	}
	if err := db.Create(first).Error; err != nil {
		t.Fatalf("第一条应写入成功: %v", err)
	}

	second := &model.EmailCode{
		Email: "dup@example.com", Scene: "reset", CodeHash: "h2",
		ExpireAt: time.Now().Add(time.Hour), MailID: 7,
	}
	if err := db.Create(second).Error; err == nil {
		t.Fatal("同一封邮件不得激活出第二条验证码（一次性语义会被破坏）")
	}

	// mail_id 为 0 的记录（历史数据/手工插入）不受约束。
	if err := db.Create(&model.EmailCode{
		Email: "legacy@example.com", Scene: "reset", CodeHash: "h3",
		ExpireAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("mail_id 为 0 的记录不该受唯一约束影响: %v", err)
	}
}

// TestDedupeMailCredentials 覆盖「旧版本留下的重复凭据」。
//
// 同一封邮件激活出多条验证码时，未使用的那些**仍然可用**——一次性语义已经破了。
// 只告警不清理的话，唯一索引也建不上，等于漏洞一直开着。
func TestDedupeMailCredentials(t *testing.T) {
	db := newTestDB(t)

	// 模拟旧数据：先去掉唯一索引，才能插进重复行。
	if err := db.Exec(`DROP INDEX IF EXISTS idx_lt_email_codes_mail_uniq`).Error; err != nil {
		t.Fatalf("删索引失败: %v", err)
	}

	old := &model.EmailCode{
		Email: "dup@example.com", Scene: "reset", CodeHash: "old-hash",
		ExpireAt: time.Now().Add(time.Hour), MailID: 42,
	}
	newer := &model.EmailCode{
		Email: "dup@example.com", Scene: "reset", CodeHash: "new-hash",
		ExpireAt: time.Now().Add(time.Hour), MailID: 42,
	}
	for _, row := range []*model.EmailCode{old, newer} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("写入重复记录失败: %v", err)
		}
	}

	if err := dedupeMailCredentials(db); err != nil {
		t.Fatalf("清理失败: %v", err)
	}

	var rows []model.EmailCode
	if err := db.Where("mail_id = ?", 42).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("同一封邮件应只保留一条凭据，实际 %d 条", len(rows))
	}
	if rows[0].CodeHash != "new-hash" {
		t.Fatalf("应保留最新的一条（id 最大），实际 %q", rows[0].CodeHash)
	}

	// 清理之后唯一索引应能建起来。
	if err := db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_lt_email_codes_mail_uniq
		 ON lt_email_codes(mail_id) WHERE mail_id > 0`).Error; err != nil {
		t.Fatalf("清理后应能建立唯一索引: %v", err)
	}

	// 幂等：再跑一次不该报错。
	if err := dedupeMailCredentials(db); err != nil {
		t.Fatalf("重复清理应幂等: %v", err)
	}
}

// TestOpenRefusesWhenCredentialCleanupFails 覆盖「清理不掉还照常启动」。
//
// 建不起唯一索引时，旧库里同一封邮件对应的多条未使用凭据仍然可用，
// 而运行期不会有任何报错。与其带着这个洞跑，不如让启动失败、先修数据。
func TestOpenRefusesWhenCredentialCleanupFails(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "dirty.db")
	cfg := &config.Config{DBDriver: "sqlite", DBDSN: dsn}

	// 先手工造一个「有重复凭据、且删不掉」的库：用一个拒绝删除的触发器模拟
	// 清理失败（真实原因可能是权限或数据损坏）。
	raw, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := raw.AutoMigrate(&model.EmailCode{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	for _, h := range []string{"a", "b"} {
		if err := raw.Create(&model.EmailCode{
			Email: "dup@example.com", Scene: "reset", CodeHash: h,
			ExpireAt: time.Now().Add(time.Hour), MailID: 9,
		}).Error; err != nil {
			t.Fatalf("造重复数据失败: %v", err)
		}
	}
	if err := raw.Exec(`CREATE TRIGGER block_mail_delete BEFORE DELETE ON lt_email_codes
		BEGIN SELECT RAISE(ABORT, 'blocked'); END`).Error; err != nil {
		t.Fatalf("装触发器失败: %v", err)
	}
	sqlDB, err := raw.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()

	if _, err := Open(cfg); err == nil {
		t.Fatal("清理重复凭据失败时必须拒绝启动（否则一次性语义仍可被绕过）")
	}
}

// TestPurgeLegacyMailDrafts 覆盖「升级遗留的草稿邮件」。
//
// 旧版本用 draft 表示「已写好、待复核额度」：进程若在复核与释放之间崩溃，
// 库里会留下这种行。正文与参数里是**明文验证码/重置链接**，而清理任务只回收
// failed / sent——不处理的话这些内容会永久留在库里，还会被发信额度统计进去。
func TestPurgeLegacyMailDrafts(t *testing.T) {
	db := newTestDB(t)

	row := &model.MailOutbox{
		To:      "legacy@example.com",
		Subject: "s",
		Body:    "code=123456",
		Payload: `{"code_hash":"deadbeef"}`,
		Kind:    model.MailKindEmailCodeReset,
		Status:  model.MailDraft,
		NextAt:  time.Now(),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("写入草稿失败: %v", err)
	}

	if err := purgeLegacyMailDrafts(db); err != nil {
		t.Fatalf("清理失败: %v", err)
	}

	var got model.MailOutbox
	if err := db.First(&got, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.MailFailed {
		t.Fatalf("遗留草稿应被标为失败，实际 %q", got.Status)
	}
	if got.Body != "" || got.Payload != "" {
		t.Fatalf("遗留草稿的正文与参数必须清空（含明文验证码），实际 body=%q payload=%q",
			got.Body, got.Payload)
	}

	// 幂等：再跑一次不该报错，也不该改动别的行。
	other := &model.MailOutbox{
		To: "normal@example.com", Subject: "s", Kind: model.MailKindResetLink,
		Status: model.MailPending, NextAt: time.Now(),
	}
	if err := db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	if err := purgeLegacyMailDrafts(db); err != nil {
		t.Fatalf("重复清理应幂等: %v", err)
	}
	var after model.MailOutbox
	if err := db.First(&after, other.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Status != model.MailPending {
		t.Fatalf("正常待发邮件不该被清理，实际 %q", after.Status)
	}
}
