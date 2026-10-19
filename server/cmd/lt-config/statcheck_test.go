package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecideLeftoverBackupThreeWay(t *testing.T) {
	cases := []struct {
		state fileState
		want  backupAction
	}{
		{fileMissing, backupRestore},
		{fileExists, backupDrop},
		{fileUnknown, backupKeep},
	}
	for _, c := range cases {
		if got := decideLeftoverBackup(c.state); got != c.want {
			t.Errorf("state=%v 时应当返回 %v，实际 %v", c.state, c.want, got)
		}
	}
	if decideLeftoverBackup(fileUnknown) == backupRestore {
		t.Error("判不出来时用备份覆盖目标，等于拿旧内容顶掉正在生效的那份")
	}
	if decideLeftoverBackup(fileUnknown) == backupDrop {
		t.Error("判不出来时删掉备份，如果目标其实缺了，活动配置就凭空消失")
	}
}

func TestDecideBatchBackupThreeWay(t *testing.T) {
	cases := []struct {
		state fileState
		want  recoveryAction
	}{
		{fileMissing, recoveryCheckTarget},
		{fileExists, recoveryFromBackup},
		{fileUnknown, recoveryKeep},
	}
	for _, c := range cases {
		if got := decideBatchBackup(c.state); got != c.want {
			t.Errorf("state=%v 时应当返回 %v，实际 %v", c.state, c.want, got)
		}
	}
	if decideBatchBackup(fileUnknown) == recoveryCheckTarget {
		t.Error("判不出备份在不在时继续往下走，会把「可能已替换」的文件当成「还没替换」")
	}
}

func linkToItself(t *testing.T, path string) {
	t.Helper()
	if err := os.Symlink(path, path); err != nil {
		t.Skipf("无法创建自引用符号链接（%v），这条分支的验证在 Linux CI 上完成", err)
	}
}

func TestStatFileStateThreeWay(t *testing.T) {
	dir := t.TempDir()

	existing := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, err := statFileState(existing); state != fileExists || err != nil {
		t.Errorf("已存在的文件应归为 fileExists 且不带错误，实际 state=%v err=%v", state, err)
	}

	missing := filepath.Join(dir, "nope")
	if state, err := statFileState(missing); state != fileMissing || err != nil {
		t.Errorf("ENOENT 应归为 fileMissing 且**不**算错误，实际 state=%v err=%v", state, err)
	}

	loop := filepath.Join(dir, "loop")
	linkToItself(t, loop)
	state, err := statFileState(loop)
	if state != fileUnknown {
		t.Fatalf("非 ENOENT 的 Stat 失败必须归为 fileUnknown，实际 %v", state)
	}
	if err == nil {
		t.Error("fileUnknown 必须带回原始错误，否则日志里说不出为什么判不出来")
	}
}

func TestCleanupLeftoversDropsBackupWhenTargetExists(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(target, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bak := target + backupSuffix
	if err := os.WriteFile(bak, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	blocked := cleanupLeftovers(paths{
		deployDir: dir,
		caddyOut:  target,
		frpsOut:   filepath.Join(dir, "frps.toml"),
		envFile:   filepath.Join(dir, ".env"),
	})

	if len(blocked) != 0 {
		t.Errorf("目标文件在时不该阻断目录，实际 %v", blocked)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("目标文件在时，遗留备份应当被删掉（否则每次启动都多留一份旧凭据）")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "new\n" {
		t.Errorf("删备份不能动目标文件，实际 %q / %v", raw, err)
	}
}

func TestCleanupLeftoversRestoresBackupWhenTargetMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	bak := target + backupSuffix
	if err := os.WriteFile(bak, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	blocked := cleanupLeftovers(paths{
		deployDir: dir,
		caddyOut:  target,
		frpsOut:   filepath.Join(dir, "frps.toml"),
		envFile:   filepath.Join(dir, ".env"),
	})

	if len(blocked) != 0 {
		t.Errorf("成功恢复不该阻断目录，实际 %v", blocked)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "old\n" {
		t.Fatalf("备份应被恢复回原位，实际 %q / %v", raw, err)
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Error("恢复之后备份不该继续留在部署目录里")
	}
}

func TestCleanupLeftoversKeepsSceneOnUnknownTargetStat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	linkToItself(t, target)
	if state, _ := statFileState(target); state != fileUnknown {
		t.Skip("这条路径没有产生非 ENOENT 的 Stat 失败，无法覆盖本分支")
	}
	bak := target + backupSuffix
	if err := os.WriteFile(bak, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	blocked := cleanupLeftovers(paths{
		deployDir: dir,
		caddyOut:  target,
		frpsOut:   filepath.Join(dir, "frps.toml"),
		envFile:   filepath.Join(dir, ".env"),
	})

	if len(blocked) != 1 || blocked[0] != dir {
		t.Fatalf("判不出目标在不在时必须阻断该目录，实际 %v", blocked)
	}
	raw, err := os.ReadFile(bak)
	if err != nil || string(raw) != "old\n" {
		t.Fatalf("判不出来时备份必须原样保留（它是仅存的一份），实际 %q / %v", raw, err)
	}
}

func TestRecoverBatchKeepsSceneOnUnknownBackupStat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	bak := target + backupSuffix
	linkToItself(t, bak)
	if state, _ := statFileState(bak); state != fileUnknown {
		t.Skip("这条路径没有产生非 ENOENT 的 Stat 失败，无法覆盖本分支")
	}

	m := batchManifest{
		Version: 1,
		Dir:     dir,
		Files: []manifestEntry{
			{Name: "Caddyfile", Path: target, Existed: true},
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, batchManifestName)
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	real, rerr := resolveManagedPath(target)
	if rerr != nil {
		t.Fatalf("解析受管路径失败: %v", rerr)
	}
	if recoverBatch(dir, map[string]bool{real: true}) {
		t.Fatal("备份在不在判不出来时必须报告「还没确定」，否则调用方会按已落定删掉记录")
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("报告未确定时必须保留批次记录（它是恢复的唯一索引）: %v", err)
	}
}
