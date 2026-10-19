package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func statErrorPath(t *testing.T, dir string) string {
	t.Helper()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("构造占位文件失败: %v", err)
	}
	return filepath.Join(blocker, "target.txt")
}

func TestWriteManifestAbortsOnNonNotExistStatError(t *testing.T) {
	dir := t.TempDir()
	bad := statErrorPath(t, dir)
	if _, err := os.Stat(bad); err == nil || os.IsNotExist(err) {
		t.Skipf("平台把路径中间是文件的情况报成了不存在，无法构造非 ENOENT 的 Stat 错误: %v", err)
	}

	b := &writeBatch{changed: map[string]bool{}}
	b.staged = append(b.staged, &stagedFile{
		name:   "Caddyfile",
		path:   bad,
		tmp:    filepath.Join(dir, ".lt-config-tmp-a"),
		newSum: contentSum("new\n"),
	})

	if _, err := b.writeManifest(); err == nil {
		t.Fatal("Stat 返回非 ENOENT 错误时必须中止，而不能记成「文件原本不存在」")
	} else if !strings.Contains(err.Error(), bad) {
		t.Errorf("错误信息应带上出问题的路径，实际: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, batchManifestName)); !os.IsNotExist(err) {
		t.Error("判定失败时不该写下批次记录")
	}
}

func TestWriteManifestMarksMissingFileAsNotExisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")

	b, err := prepareWrites([]pendingWrite{
		{name: "Caddyfile", path: path, content: "new\n", mode: modeConfig},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.discard()

	m, err := b.writeManifest()
	if err != nil {
		t.Fatalf("目标文件不存在时不该报错: %v", err)
	}
	if len(m.Files) != 1 {
		t.Fatalf("应记录 1 个文件，实际 %d", len(m.Files))
	}
	if m.Files[0].Existed {
		t.Error("不存在的目标文件必须记 Existed=false，否则回滚会试图从备份恢复一个从未存在过的文件")
	}

	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := prepareWrites([]pendingWrite{
		{name: "Caddyfile", path: path, content: "new\n", mode: modeConfig},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b2.discard()
	m2, err := b2.writeManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Files[0].Existed {
		t.Error("已存在的目标文件必须记 Existed=true，否则回滚会删掉本该保留的文件")
	}
}

func TestStagedFileCommitAbortsOnNonNotExistStatError(t *testing.T) {
	dir := t.TempDir()
	bad := statErrorPath(t, dir)
	if _, err := os.Stat(bad); err == nil || os.IsNotExist(err) {
		t.Skipf("平台把路径中间是文件的情况报成了不存在，无法构造非 ENOENT 的 Stat 错误: %v", err)
	}

	st := &stagedFile{name: "Caddyfile", path: bad, tmp: filepath.Join(dir, ".lt-config-tmp-x")}
	if err := os.WriteFile(st.tmp, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer st.discard()

	err := st.commit()
	if err == nil {
		t.Fatal("Stat 返回非 ENOENT 错误时必须中止替换")
	}
	if !strings.Contains(err.Error(), "备份") {
		t.Errorf("错误信息应说明无法确定是否需要备份，实际: %v", err)
	}
	if st.existed {
		t.Error("判不出来时不能把 existed 记成 true，那会让回滚去恢复一份不存在的内容")
	}
	if _, serr := os.Stat(st.tmp); serr != nil {
		t.Errorf("中止时不该动候选内容（临时文件应仍在）: %v", serr)
	}
}

func TestStagedFileCommitRestoresOnENOENT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")

	st := &stagedFile{name: "Caddyfile", path: path, tmp: filepath.Join(dir, ".lt-config-tmp-y")}
	if err := os.WriteFile(st.tmp, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.commit(); err != nil {
		t.Fatalf("目标不存在时 commit 应当成功: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "new\n" {
		t.Fatalf("目标应是新内容，实际 %q / %v", raw, err)
	}
	if st.existed {
		t.Error("原本不存在的文件不能记 existed=true")
	}
	if st.backup != "" {
		t.Error("原本不存在的文件不该产生备份")
	}
	if err := st.restore(); err != nil {
		t.Fatalf("恢复应当成功: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("回滚原本不存在的文件 = 删掉新文件")
	}
}

func TestRollbackFailedCommitReportsCleanupPending(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, batchManifestName)
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	b := &writeBatch{changed: map[string]bool{}}
	cause := errors.New("模拟替换失败")
	err := b.rollbackFailedCommit(batchManifest{Dir: dir}, "Caddyfile", cause)
	if err == nil {
		t.Fatal("记录删不掉时必须返回错误")
	}
	if !errors.Is(err, errBatchCleanupPending) {
		t.Fatalf("必须返回可被 errBatchCleanupPending 识别的错误，实际 %v", err)
	}
	if !errors.Is(err, cause) {
		t.Error("原始替换错误必须可被追溯（%w 包装）")
	}
	for _, want := range []string{"已回滚", "批次记录", "重启"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息应说明「%s」的后果，实际: %v", want, err)
		}
	}
}

func TestRollbackFailedCommitCleansUpNormally(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, batchManifestName)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	b := &writeBatch{changed: map[string]bool{}}
	cause := errors.New("模拟替换失败")
	err := b.rollbackFailedCommit(batchManifest{Dir: dir}, "Caddyfile", cause)
	if err == nil {
		t.Fatal("替换失败必须返回错误")
	}
	if errors.Is(err, errBatchCleanupPending) {
		t.Error("记录已经删掉时不该报「现场未清理」")
	}
	if !strings.Contains(err.Error(), "已回滚") {
		t.Errorf("错误里应说明已回滚，实际: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Error("原始错误必须可被追溯")
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Error("记录应当已被删除")
	}
}

func TestCommitFailureRegistersDirtyScene(t *testing.T) {
	s, p := newRenderOnlyService(t)

	cleanupErr := fmt.Errorf("%w: 替换 Caddyfile 失败，已回滚（磁盘仍为旧配置），但批次记录未能删除", errBatchCleanupPending)
	got := s.commitFailure(cleanupErr)
	if got == nil {
		t.Fatal("commitFailure 不该把错误吞掉")
	}
	if !errors.Is(got, errBatchCleanupPending) {
		t.Errorf("错误链上必须仍能识别出 errBatchCleanupPending，实际 %v", got)
	}
	var partial *partialApplyError
	if !errors.As(got, &partial) {
		t.Fatalf("现场未清理必须报 partial（磁盘已回滚、容器状态未知），实际类型 %T", got)
	}
	if len(partial.services) != 0 {
		t.Logf("容器状态: %v", partial.services)
	}
	if dir := s.dirtyDir(); dir == "" {
		t.Fatal("批次记录删不掉时必须登记运行时阻断，否则后续写盘会覆盖唯一可恢复的现场")
	} else if dir != p.deployDir {
		t.Errorf("阻断的目录应当是部署产物所在目录，实际 %q", dir)
	}

	s2, _ := newRenderOnlyService(t)
	plain := s2.commitFailure(errors.New("替换 Caddyfile 失败，已回滚（磁盘仍为旧配置）"))
	if errors.Is(plain, errBatchCleanupPending) {
		t.Error("普通失败不该被报成现场未清理")
	}
	var partial2 *partialApplyError
	if errors.As(plain, &partial2) {
		t.Error("普通失败应当按内部错误返回，而不是 partial")
	}
	if dir := s2.dirtyDir(); dir != "" {
		t.Errorf("普通失败不该登记阻断，实际阻断 %q", dir)
	}
}
