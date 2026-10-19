package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type pendingWrite struct {
	name    string
	path    string
	content string
	mode    os.FileMode
}

type writeBatch struct {
	staged    []*stagedFile
	changed   map[string]bool
	warn      []string
	done      int
	manifest  batchManifest
	modeFix   []pendingModeFix
	modeFixed bool
}

type pendingModeFix struct {
	name     string
	path     string
	mode     os.FileMode
	original os.FileMode
}

func pendingChanges(writes []pendingWrite) []string {
	var names []string
	for _, w := range writes {
		old, err := os.ReadFile(w.path)
		if err == nil && string(old) == w.content {
			continue
		}
		names = append(names, w.name)
	}
	return names
}

func prepareWrites(writes []pendingWrite) (*writeBatch, error) {
	b := &writeBatch{changed: map[string]bool{}}
	for _, w := range writes {
		if fi, err := os.Lstat(w.path); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				b.discard()
				return nil, fmt.Errorf("%s 的目标路径是符号链接，拒绝替换: %s", w.name, w.path)
			}
			if !fi.Mode().IsRegular() {
				b.discard()
				return nil, fmt.Errorf("%s 的目标路径不是普通文件（%s），拒绝替换: %s", w.name, fi.Mode().Type(), w.path)
			}
		} else if !os.IsNotExist(err) {
			b.discard()
			return nil, fmt.Errorf("检查 %s 的目标路径失败: %w", w.name, err)
		}
		if old, err := os.ReadFile(w.path); err == nil && string(old) == w.content {
			if fi, err := os.Stat(w.path); err != nil || fi.Mode().Perm() != w.mode.Perm() {
				var orig os.FileMode
				if err == nil {
					orig = fi.Mode().Perm()
				}
				b.modeFix = append(b.modeFix, pendingModeFix{
					name: w.name, path: w.path, mode: w.mode, original: orig,
				})
			}
			continue
		}
		st, err := stageFile(w.name, w.path, w.content, w.mode)
		if err != nil {
			b.discard()
			return nil, fmt.Errorf("准备写入 %s 失败: %w", w.name, err)
		}
		b.staged = append(b.staged, st)
		b.changed[w.name] = true
	}
	return b, nil
}

func (b *writeBatch) applyModeFixes() {
	for _, fix := range b.modeFix {
		if err := os.Chmod(fix.path, fix.mode.Perm()); err != nil {
			b.warn = append(b.warn,
				fmt.Sprintf("%s 的内容没变，但权限纠正失败（期望 %#o）: %v", fix.name, fix.mode.Perm(), err))
			continue
		}
		b.modeFixed = true
		b.warn = append(b.warn,
			fmt.Sprintf("%s 的内容没变，权限已收紧为 %#o", fix.name, fix.mode.Perm()))
	}
}

func (b *writeBatch) restoreModeFixes() error {
	if !b.modeFixed {
		return nil
	}
	var failures []string
	for _, fix := range b.modeFix {
		if fix.original == 0 {
			continue
		}
		if err := os.Chmod(fix.path, fix.original); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", fix.name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("恢复文件权限失败: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (b *writeBatch) commit() error {
	if len(b.staged) == 0 {
		b.applyModeFixes()
		return nil
	}
	m, err := b.writeManifest()
	if err != nil {
		b.discard()
		return batchManifestError(err)
	}
	b.manifest = m

	for i := range b.staged {
		st := b.staged[i]
		if err := st.commit(); err != nil {
			rbErr := b.rollbackCommitted()
			b.discardFrom(i)
			if rbErr != nil {
				return fmt.Errorf("替换 %s 失败，且回滚未完成（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", st.name, err, rbErr)
			}
			return b.rollbackFailedCommit(m, st.name, err)
		}
		b.done++
	}
	if err := b.refreshBackupSums(); err != nil {
		rbErr := b.rollbackCommitted()
		if rbErr != nil {
			return fmt.Errorf("补写备份摘要失败，且回滚未完成（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", err, rbErr)
		}
		return b.rollbackFailedCommit(m, "备份摘要", err)
	}

	b.applyModeFixes()

	return nil
}

func (s *service) commitFailure(err error) error {
	if !errors.Is(err, errBatchCleanupPending) {
		return internalError(err)
	}
	s.registerDirtyScene()
	statesCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	states, stateErr := s.serviceStates(statesCtx)
	return &partialApplyError{
		msg: fmt.Sprintf("本次写盘已回滚（磁盘仍为旧配置），但批次现场未能清理："+
			"重启后恢复逻辑会按残留记录把整批再回滚一次、覆盖此后的任何修改；"+
			"在人工清理之前，所有写操作都会被拒绝\n%v", err),
		services:    states,
		servicesErr: stateErr,
		cause:       err,
	}
}

func (b *writeBatch) discard() { b.discardFrom(0) }

func (b *writeBatch) discardFrom(i int) {
	for _, st := range b.staged[i:] {
		st.discard()
	}
}
