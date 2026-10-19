package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (s *service) registerDirtyScene() {
	dirs := make([]string, 0, 3)
	seen := make(map[string]struct{}, 3)
	for _, f := range []string{s.paths.caddyOut, s.paths.frpsOut, s.paths.envFile} {
		dir := filepath.Dir(f)
		if dir != "" {
			if _, ok := seen[dir]; !ok {
				seen[dir] = struct{}{}
				dirs = append(dirs, dir)
			}
		}
	}
	s.blockedMu.Lock()
	defer s.blockedMu.Unlock()
	for _, dir := range dirs {
		found := false
		for _, existing := range s.blockedDirs {
			if existing == dir {
				found = true
				break
			}
		}
		if !found {
			s.blockedDirs = append(s.blockedDirs, dir)
		}
	}
}

func (s *service) dirtyDir() string {
	s.blockedMu.RLock()
	defer s.blockedMu.RUnlock()
	if len(s.blockedDirs) == 0 {
		return ""
	}
	for _, f := range []string{s.paths.caddyOut, s.paths.frpsOut, s.paths.envFile} {
		dir := filepath.Dir(f)
		for _, b := range s.blockedDirs {
			if b != "" && b == dir {
				return dir
			}
		}
	}
	return ""
}

func (s *service) dirtySceneError(dir string) error {
	return fmt.Errorf(
		"部署目录 %s 存在上次提交未能自动收敛的现场：批次记录里的摘要与磁盘上的备份/目标文件对不上，"+
			"自动恢复已停止。为避免覆盖唯一可恢复的备份，本次写盘被拒绝。"+
			"请人工确认 %s 与 *%s 的内容，保留需要的那一份后手工清理，再重新应用",
		dir, batchManifestName, backupSuffix)
}

func syncDirBestEffort(dir string) {
	if dir == "" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
