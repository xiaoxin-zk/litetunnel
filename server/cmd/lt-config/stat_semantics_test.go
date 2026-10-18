package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组守的是「Stat 失败 ≠ 文件不存在」。
//
// 权限不足、路径被占用、I/O 出错时 os.Stat 同样返回 err，而且 err 不是
// ENOENT。早期实现用 `err == nil` 判断「文件在」，于是这些失败被读成
// 「目标文件本来就不存在」：备份不写，提交后崩溃就再也没有旧内容可恢复。
// 只有 os.IsNotExist 才算「不存在」，其余必须中止。

// statErrorPath 构造一个能让 os.Stat 返回**非 ENOENT** 错误的路径，
// 且不依赖权限设置（CI 以 root 跑的时候 chmod 根本挡不住）。
//
// 做法：在路径中间放一个普通文件，让 Stat 去解析 `<file>/x`。
//
//   - Linux：内核返回 ENOTDIR（"not a directory"），os.IsNotExist 为假，
//     正是要构造的那种「判不出来」的 Stat 失败；
//   - Windows：Go 的 syscall.Errno.Is 把 ERROR_PATH_NOT_FOUND 也算作
//     ErrNotExist（os.IsNotExist 会返回 true），构造不出来。
//
// 所以 Windows 上这条路走不通，两个用例会用 os.IsNotExist 自检后 t.Skip。
// 这条性质的有效验证在 Linux CI（ubuntu-latest）上完成——本机是 Windows，
// 跳过不等于没覆盖，只是覆盖发生在 CI。
func statErrorPath(t *testing.T, dir string) string {
	t.Helper()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("构造占位文件失败: %v", err)
	}
	return filepath.Join(blocker, "target.txt")
}

// TestWriteManifestAbortsOnNonNotExistStatError 覆盖批次记录里的 Existed 判定。
//
// 这里必须先确认「构造出来的确实是非 ENOENT 错误」，否则整个用例只是空转：
// 如果平台把这种路径也报成不存在（Windows 就把 ERROR_PATH_NOT_FOUND 归为
// ErrNotExist），断言会变得毫无意义，于是直接跳过——真正的验证在
// Linux CI 上完成。
//
// 直接构造 writeBatch 而不用 prepareWrites：后者会在同一个（其实是文件的）
// 父目录里建临时文件，更早就失败了，测不到 writeManifest 的判定。
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
		// 错误串必须带路径：否则管理员不知道是哪个文件判不出来。
		t.Errorf("错误信息应带上出问题的路径，实际: %v", err)
	}
	// 中止必须发生在写入批次记录之前：此刻一个目标文件都没动，不该留下记录。
	if _, err := os.Stat(filepath.Join(dir, batchManifestName)); !os.IsNotExist(err) {
		t.Error("判定失败时不该写下批次记录")
	}
}

// TestWriteManifestMarksMissingFileAsNotExisted 是上面的对照组：
// 真的不存在（ENOENT）时仍然要记 Existed=false 并继续，否则「新建文件」
// 这条正常路径会被误伤。
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

	// 已存在时记 Existed=true。
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

// TestStagedFileCommitAbortsOnNonNotExistStatError 覆盖 stagedFile.commit：
// 判不出「目标在不在」时不能在没有任何备份的情况下替换。
func TestStagedFileCommitAbortsOnNonNotExistStatError(t *testing.T) {
	dir := t.TempDir()
	bad := statErrorPath(t, dir)
	if _, err := os.Stat(bad); err == nil || os.IsNotExist(err) {
		t.Skipf("平台把路径中间是文件的情况报成了不存在，无法构造非 ENOENT 的 Stat 错误: %v", err)
	}

	// stagedFile 的临时文件必须与目标同目录，这里手工构造一个。
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
	// 中止发生在动目标之前：临时文件还在，调用方还能重试或丢弃。
	if _, serr := os.Stat(st.tmp); serr != nil {
		t.Errorf("中止时不该动候选内容（临时文件应仍在）: %v", serr)
	}
}

// TestStagedFileCommitRestoresOnENOENT 对照组：目标真的不存在时，
// commit 必须正常成功，回滚语义是「删掉新文件」而不是「放回备份」。
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

// TestRollbackFailedCommitReportsCleanupPending 覆盖问题 3 的核心：
// 已回滚但批次记录删不掉时必须能被 errors.Is(err, errBatchCleanupPending)
// 识别，而不是静默返回一句「已回滚」。
func TestRollbackFailedCommitReportsCleanupPending(t *testing.T) {
	dir := t.TempDir()
	// 用目录占住记录路径：os.Remove 对非空目录一定失败（各平台一致）。
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

// TestRollbackFailedCommitCleansUpNormally 对照组：记录删得掉时行为不变，
// 不能因为新增了阻断判定就把普通失败也报成「现场未清理」。
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

// TestCommitFailureRegistersDirtyScene 守住「调用方必须阻断」这一环：
// 只要 commit 返回 errBatchCleanupPending，renderAndApply 就要把目录登记进
// 阻断集合（经 commitFailure），之后所有写操作被挡住，直到人工清理。
//
// 这里直接覆盖 commitFailure 而不是跑整个 renderAndApply：后者的前置条件
// （docker 校验、模板渲染）与本条判定无关，走完整流程只会让用例更脆。
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
		// 测试环境没有 docker，serviceStates 必然为空——这里只是确认它被调用
		// 过而不是 panic。
		t.Logf("容器状态: %v", partial.services)
	}
	if dir := s.dirtyDir(); dir == "" {
		t.Fatal("批次记录删不掉时必须登记运行时阻断，否则后续写盘会覆盖唯一可恢复的现场")
	} else if dir != p.deployDir {
		t.Errorf("阻断的目录应当是部署产物所在目录，实际 %q", dir)
	}

	// 普通写盘失败不能被误判成「现场未清理」：那会让一次可以重试的失败
	// 变成必须人工介入的阻断。
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
