package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 这一组守的是「Stat 失败 ≠ 文件不存在」在两处**启动清理**判定上的落点。
//
// 两处都属于「猜错就删掉唯一可恢复的那份内容」：
//
//   - cleanupLeftovers 遇到 *.lt-config-bak：旧实现是
//     `if os.IsNotExist(err) { 恢复 } else { 删备份 }`。非 ENOENT 的 Stat 失败
//     落进 else，被读成「目标在，备份是旧的」，于是删掉活动配置的唯一副本。
//   - recoverBatch 遇到某个文件的备份：旧实现是
//     `if _, err := os.Stat(bak); err == nil { 恢复 }`。非 ENOENT 的失败落进
//     「没有备份」，而那条路最终可能把记录当成已落定删掉。
//
// 判定本身被摘成纯函数（statcheck.go），所以三分支能在这里被逐一钉住，
// 不依赖能否在测试里稳定构造出非 ENOENT 的 Stat 错误。后面几个用例再用
// 自引用的符号链接（Stat 返回 ELOOP，不是 ENOENT）走一遍真实路径。

// TestDecideLeftoverBackupThreeWay 钉住遗留备份的三分支。
//
// 这条判定是「删不删备份」的唯一开关：一旦 fileUnknown 被归到 backupDrop，
// 一次权限不足就会永久删掉活动配置的最后一份副本。
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
	// 判不出来时既不能恢复也不能删除：两个方向都会做出无法撤回的动作。
	if decideLeftoverBackup(fileUnknown) == backupRestore {
		t.Error("判不出来时用备份覆盖目标，等于拿旧内容顶掉正在生效的那份")
	}
	if decideLeftoverBackup(fileUnknown) == backupDrop {
		t.Error("判不出来时删掉备份，如果目标其实缺了，活动配置就凭空消失")
	}
}

// TestDecideBatchBackupThreeWay 钉住批次回滚的备份三分支。
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

// linkToItself 在 path 处放一个指向自己的符号链接。
//
// 这是**唯一**能跨平台地让 os.Stat 返回「非 ENOENT 错误」而路径本身又不需要
// 父目录异常的手法：解析符号链接时内核发现循环，返回 ELOOP，而 ELOOP 不是
// ErrNotExist——正是「判不出来」那种情况。
//
// 用不了就用不了：Windows 上创建符号链接需要开发者模式或管理员权限，普通
// 账户会失败。此时跳过并在日志里说明——有效验证在 Linux CI（ubuntu-latest）
// 上完成。
func linkToItself(t *testing.T, path string) {
	t.Helper()
	if err := os.Symlink(path, path); err != nil {
		t.Skipf("无法创建自引用符号链接（%v），这条分支的验证在 Linux CI 上完成", err)
	}
}

// TestStatFileStateThreeWay 用真实文件系统确认三态归类。
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

// TestCleanupLeftoversDropsBackupWhenTargetExists：目标在，备份就是替换前留下
// 的旧内容，删掉它，且**不能**因此阻断目录（否则一次正常启动就永久禁止写盘）。
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

// TestCleanupLeftoversRestoresBackupWhenTargetMissing：目标缺失，备份是这份活动
// 配置仅存的一份，必须放回原位——否则启动校验会直接报「缺少 .env」。
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

// TestCleanupLeftoversKeepsSceneOnUnknownTargetStat 是缺陷 8 的核心回归：
// 判不出目标在不在时，**既不能删也不能恢复**，必须原样保留并阻断目录。
//
// 旧实现在这里是「删备份」——那一支删掉的正是活动配置的最后一份副本。
func TestCleanupLeftoversKeepsSceneOnUnknownTargetStat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	// 自引用符号链接：Stat(target) 返回 ELOOP（非 ENOENT），即「判不出来」。
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

// TestRecoverBatchKeepsSceneOnUnknownBackupStat 覆盖批次回滚那一侧：
// 判不出某个文件的备份在不在时，必须记成失败、保留批次记录。
//
// 旧实现把它当成「没有备份」，于是往下走「目标是不是已经是新内容」的核对；
// 若恰好都对不上，这一批会被当成已落定，记录随之删除。
func TestRecoverBatchKeepsSceneOnUnknownBackupStat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Caddyfile")
	bak := target + backupSuffix
	// 备份路径本身是个自引用符号链接：Stat(bak) 返回 ELOOP。
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

	if recoverBatch(dir) {
		t.Fatal("备份在不在判不出来时必须报告「还没确定」，否则调用方会按已落定删掉记录")
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("报告未确定时必须保留批次记录（它是恢复的唯一索引）: %v", err)
	}
}
