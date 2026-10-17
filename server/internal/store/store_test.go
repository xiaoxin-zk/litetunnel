package store

import (
	"path/filepath"
	"testing"
	"time"

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
