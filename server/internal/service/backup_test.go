package service

import (
	"errors"
	"os"
	"testing"
)

func TestBackupCreateListDelete(t *testing.T) {
	svc := newTestServices(t, nil)

	file, err := svc.CreateBackup("")
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	if file.Size <= 0 {
		t.Fatalf("备份文件不应为空，实际 %d 字节", file.Size)
	}

	items, err := svc.ListBackups()
	if err != nil {
		t.Fatalf("读取备份列表失败: %v", err)
	}
	if len(items) != 1 || items[0].Name != file.Name {
		t.Fatalf("列表内容不正确: %+v", items)
	}

	path, err := svc.BackupFilePath(file.Name)
	if err != nil {
		t.Fatalf("解析备份路径失败: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("备份文件不存在: %v", err)
	}

	if err := svc.DeleteBackup(file.Name); err != nil {
		t.Fatalf("删除备份失败: %v", err)
	}
	if err := svc.DeleteBackup(file.Name); !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("重复删除应返回不存在，实际 %v", err)
	}
}

func TestBackupRetentionKeepsNewest(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyBackupRetention: "2"}); err != nil {
		t.Fatalf("保存保留份数失败: %v", err)
	}

	for _, tag := range []string{"-a", "-b", "-c"} {
		if _, err := svc.CreateBackup(tag); err != nil {
			t.Fatalf("创建备份 %s 失败: %v", tag, err)
		}
	}

	items, err := svc.ListBackups()
	if err != nil {
		t.Fatalf("读取备份列表失败: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("保留 2 份时应只剩 2 个文件，实际 %d 个", len(items))
	}
	for _, it := range items {
		if it.PreRestore {
			t.Fatalf("普通备份不该带 pre-restore 标记: %s", it.Name)
		}
	}
}

func TestBackupRejectsPathTraversal(t *testing.T) {
	svc := newTestServices(t, nil)

	for _, name := range []string{"../evil.db", "sub/evil.db", "", "evil.txt", "/etc/passwd.db"} {
		if _, err := svc.BackupFilePath(name); !errors.Is(err, ErrBackupNameInvalid) {
			t.Fatalf("非法文件名 %q 应被拒绝，实际 %v", name, err)
		}
	}
	if err := svc.RestoreBackup("nope.db"); !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("不存在的备份应返回不存在，实际 %v", err)
	}
}

func TestBackupUnsupportedDriver(t *testing.T) {
	svc := newTestServices(t, nil)
	driver := svc.Cfg.DBDriver
	svc.Cfg.DBDriver = "postgres"
	defer func() { svc.Cfg.DBDriver = driver }()

	if svc.BackupSupported() {
		t.Fatal("PostgreSQL 不该被标记为支持在线备份")
	}
	if _, err := svc.CreateBackup(""); !errors.Is(err, ErrBackupUnsupported) {
		t.Fatalf("不支持时创建备份应明确报错，实际 %v", err)
	}
	if err := svc.RestoreBackup("x.db"); !errors.Is(err, ErrBackupUnsupported) {
		t.Fatalf("不支持时恢复应明确报错，实际 %v", err)
	}
}
