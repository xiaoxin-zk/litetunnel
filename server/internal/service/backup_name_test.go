package service

import "testing"

// 同一秒内连续备份不能互相覆盖：文件名精确到毫秒，重名时再自增。
func TestCreateBackupUsesUniqueNames(t *testing.T) {
	svc := newTestServices(t, nil)

	first, err := svc.CreateBackup("")
	if err != nil {
		t.Fatalf("第一次备份失败: %v", err)
	}
	second, err := svc.CreateBackup("")
	if err != nil {
		t.Fatalf("第二次备份失败: %v", err)
	}
	if first.Name == second.Name {
		t.Fatalf("两次备份用了同一个文件名 %q，后一份会覆盖前一份", first.Name)
	}

	list, err := svc.ListBackups()
	if err != nil {
		t.Fatalf("读取备份列表失败: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("应至少保留两份备份，实际 %d 份", len(list))
	}
}
