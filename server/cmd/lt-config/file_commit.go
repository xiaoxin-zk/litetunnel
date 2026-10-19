package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

type stagedFile struct {
	name    string
	path    string
	tmp     string
	backup  string
	existed bool

	newSum string
	bakSum string
}

func stageFile(name, path, content string, mode os.FileMode) (*stagedFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".lt-config-tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	st := &stagedFile{name: name, path: path, tmp: tmp, newSum: contentSum(content)}

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Close(); err != nil {
		st.discard()
		return nil, err
	}
	return st, nil
}

func (s *stagedFile) commit() error {
	state, err := statFileState(s.path)
	if state == fileUnknown {
		return fmt.Errorf("检查目标文件是否存在失败（无法确定是否需要备份 %s）: %w", s.path, err)
	}
	if state == fileExists {
		s.existed = true
		backup := s.path + backupSuffix
		if err := os.Rename(s.path, backup); err != nil {
			return fmt.Errorf("备份旧文件失败: %w", err)
		}
		s.backup = backup
		if sum, err := fileSum(backup); err != nil {
			log.Printf("[lt-config] 计算备份摘要失败（%s），恢复时将退回报份存在性判断: %v", backup, err)
		} else {
			s.bakSum = sum
		}
		syncDirBestEffort(filepath.Dir(s.path))
	}
	if err := os.Rename(s.tmp, s.path); err != nil {
		if rerr := s.restore(); rerr != nil {
			return fmt.Errorf("替换失败（%v），且恢复旧文件也失败: %w", err, rerr)
		}
		return err
	}
	syncDirBestEffort(filepath.Dir(s.path))
	return nil
}

func (s *stagedFile) restore() error {
	if s.backup != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(s.backup, s.path); err != nil {
			return err
		}
		s.backup = ""
		syncDirBestEffort(filepath.Dir(s.path))
		return nil
	}
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (s *stagedFile) cleanupBackup() {
	if s.backup != "" {
		_ = os.Remove(s.backup)
		s.backup = ""
	}
}

func (s *stagedFile) discard() {
	_ = os.Remove(s.tmp)
}

func writeFileAtomic(path, content string, mode os.FileMode) error {
	st, err := stageFile(filepath.Base(path), path, content, mode)
	if err != nil {
		return err
	}
	if err := st.commit(); err != nil {
		st.discard()
		return err
	}
	st.cleanupBackup()
	return nil
}

func contentSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
