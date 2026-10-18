package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// 本文件是「脏现场」的运行时阻断：把无法自动收敛的部署目录登记下来，之后所有
// 写盘请求都被拒绝，直到管理员人工清理。
//
// 为什么需要这层阻断：现场（批次记录与备份）是唯一还能修复磁盘的东西，一次新的
// 应用就会把它覆盖掉，把「还能修」变成「只能人工拼」。启动时发现现场只是第一种
// 路径；运行过程中同样可能出现——例如容器已按新配置启动，而 committed 状态写不
// 下去（见 registerDirtyScene）。
//
// syncDirBestEffort 也放在这里：它保证 rename/unlink 这类目录项变更与批次记录
// 一起落盘，是「重启后仍能按批次恢复」的前提。

// registerDirtyScene 把运行过程中无法落定的现场加入阻断集合。
//
// 启动时发现现场只是第一种路径；/render 过程中也可能在容器已经按新配置
// 启动后写不下 committed 状态。若这里只返回 partial 而不登记，当前进程的
// 下一次请求仍会覆盖 manifest 与备份，正好抹掉人工恢复所需的最后证据。
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

// dirtyDir 返回与本次写盘相关、且处于未收敛状态的目录；为空表示可以继续。
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

// dirtySceneError 说明「为什么这次拒绝执行」，并给出人工处理的办法。
//
// 只说「配置现场异常」是不够的：管理员需要知道去看哪个目录、删之前要确认什么。
func (s *service) dirtySceneError(dir string) error {
	return fmt.Errorf(
		"部署目录 %s 存在上次提交未能自动收敛的现场：批次记录里的摘要与磁盘上的备份/目标文件对不上，"+
			"自动恢复已停止。为避免覆盖唯一可恢复的备份，本次写盘被拒绝。"+
			"请人工确认 %s 与 *%s 的内容，保留需要的那一份后手工清理，再重新应用",
		dir, batchManifestName, backupSuffix)
}

// syncDirBestEffort 尽力把目录项变更刷到磁盘。
//
// 只对文件做 fsync 是不够的：rename / unlink 这些**目录项**变更由目录本身
// 记录，不同步父目录的话，突然断电后可能出现「.env 已经是新内容、批次记录
// 却不见了」——批次恢复失去唯一依据，磁盘停在半套配置上。
//
// 实现是「尽力而为」：Windows 无法以可 flush 的方式打开目录（返回
// ERROR_INVALID_HANDLE 之类），NTFS 的目录项更新由文件系统日志保证，
// 这里静默跳过。也就是说 Windows 上的恢复保证覆盖进程被强杀与正常掉电，
// 不承诺磁盘写缓存被整体丢弃的极端情形。
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
