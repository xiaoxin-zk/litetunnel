package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func readFileLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("文件 %s 超过大小上限 %d 字节", path, max)
	}
	return data, nil
}

func recoverBatch(dir string, managed map[string]bool) bool {
	path := filepath.Join(dir, batchManifestName)
	raw, err := readFileLimited(path, maxManifestBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[lt-config] 读取批次记录失败（%s）: %v", path, err)
			return false
		}
		return true
	}

	var m batchManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("[lt-config] 批次记录无法解析（%s），保留现场并阻断后续写盘: %v", path, err)
		return false
	}
	if err := validateManifestForRecovery(dir, m, managed); err != nil {
		log.Printf("[lt-config] 批次记录 schema 或路径不可信（%s），保留现场并阻断后续写盘: %v", path, err)
		return false
	}

	if m.Status == batchStatusCommitted {
		log.Printf("[lt-config] 发现已提交的批次记录（%d 个文件），清理残留备份", len(m.Files))
		for _, f := range m.Files {
			if err := os.Remove(f.Path + backupSuffix); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 清理批次备份失败（%s）: %v", f.Path, err)
				return false
			}
			if f.Tmp != "" {
				if err := os.Remove(f.Tmp); err != nil && !os.IsNotExist(err) {
					log.Printf("[lt-config] 清理批次临时文件失败（%s）: %v", f.Tmp, err)
					return false
				}
			}
		}
		if err := os.Remove(path + backupSuffix); err != nil && !os.IsNotExist(err) {
			log.Printf("[lt-config] 删除批次记录备份失败（%s）: %v", path+backupSuffix, err)
			return false
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[lt-config] 删除批次记录失败（%s）: %v", path, err)
			return false
		}
		return true
	}

	log.Printf("[lt-config] 发现未完成的批次提交（%d 个文件），按批次整体回滚", len(m.Files))
	failed := rollbackEntries(m.Files)
	for _, f := range m.Files {
		if f.Tmp != "" {
			if err := os.Remove(f.Tmp); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 回滚后清理临时文件失败（%s），保留现场: %v", f.Tmp, err)
				failed = append(failed, f.Name+" 临时文件")
			}
		}
	}

	failed = append(failed, verifyRollback(m.Files)...)

	if len(failed) > 0 {
		log.Printf("[lt-config] 批次回滚未完成（失败：%s），保留批次记录与备份，等待下次启动重试或人工处理",
			strings.Join(failed, ", "))
		return false
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("[lt-config] 删除批次记录失败（%s）: %v", path, err)
		return false
	}
	if err := os.Remove(path + backupSuffix); err != nil && !os.IsNotExist(err) {
		log.Printf("[lt-config] 删除批次记录的备份失败（%s）: %v", path, err)
		return false
	}
	return true
}

func rollbackEntries(files []manifestEntry) []string {
	var failed []string
	for _, f := range files {
		bak := f.Path + backupSuffix
		bakState, serr := statFileState(bak)
		switch decideBatchBackup(bakState) {
		case recoveryFromBackup:
			if f.BakSum != "" {
				sum, err := fileSum(bak)
				switch {
				case err != nil:
					log.Printf("[lt-config] 批次回滚：备份读不出来，拒绝盲目覆盖（%s）: %v", bak, err)
					failed = append(failed, f.Name)
					continue
				case sum != f.BakSum:
					log.Printf("[lt-config] 批次回滚：备份内容与记录摘要不符（%s），拒绝用它覆盖", bak)
					failed = append(failed, f.Name)
					continue
				}
			}
			if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 批次回滚：删除新文件失败（%s）: %v", f.Path, err)
				failed = append(failed, f.Name)
				continue
			}
			if err := os.Rename(bak, f.Path); err != nil {
				log.Printf("[lt-config] 批次回滚：恢复旧文件失败（%s）: %v", f.Path, err)
				failed = append(failed, f.Name)
				continue
			}
			log.Printf("[lt-config] 已回滚：%s", f.Name)
			continue
		case recoveryKeep:
			log.Printf("[lt-config] 批次回滚：无法判定备份是否存在（%s）: %v；保留记录与备份，等待人工确认",
				bak, serr)
			failed = append(failed, f.Name)
			continue
		}
		if f.NewSum != "" {
			if sum, err := fileSum(f.Path); err == nil && sum == f.NewSum {
				log.Printf("[lt-config] 批次回滚：%s 已是新内容但没有备份可用于恢复", f.Name)
				failed = append(failed, f.Name)
				continue
			}
		}
		if !f.Existed {
			if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 批次回滚：删除多余文件失败（%s）: %v", f.Path, err)
				failed = append(failed, f.Name)
			}
		}
	}
	return failed
}

func verifyRollback(files []manifestEntry) []string {
	var failed []string
	for _, f := range files {
		if f.BakSum == "" {
			continue
		}
		sum, err := fileSum(f.Path)
		switch {
		case err != nil:
			log.Printf("[lt-config] 批次回滚后校验失败：读不出目标文件（%s）: %v", f.Path, err)
			failed = append(failed, f.Name)
		case sum != f.BakSum:
			log.Printf("[lt-config] 批次回滚后校验失败：内容与备份摘要不符（%s）", f.Path)
			failed = append(failed, f.Name)
		}
	}
	return failed
}

func cleanupLeftovers(p paths) []string {
	var blocked []string
	blockDir := func(dir string) {
		for _, existing := range blocked {
			if existing == dir {
				return
			}
		}
		blocked = append(blocked, dir)
	}
	managed, managedErr := managedOutputPaths(p)
	if managedErr != nil {
		log.Printf("[lt-config] 无法确定受管文件白名单，本次跳过全部恢复与清理: %v", managedErr)
	}

	seen := map[string]bool{}
	for _, f := range []string{p.deployDir, p.caddyOut, p.frpsOut, p.envFile} {
		if strings.TrimSpace(f) == "" {
			continue
		}
		dir := filepath.Dir(f)
		if f == p.deployDir {
			dir = filepath.Clean(f)
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		blockedBefore := func() bool {
			for _, b := range blocked {
				if b == dir {
					return true
				}
			}
			return false
		}
		if blockedBefore() {
			log.Printf("[lt-config] %s 已属于被阻断的批次目录，跳过本轮清理", dir)
			continue
		}

		if managedErr != nil || !recoverBatch(dir, managed) {
			log.Printf("[lt-config] %s 的批次回滚未完成，跳过本次残留清理", dir)
			for _, related := range relatedBatchDirs(dir) {
				blockDir(related)
			}
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("[lt-config] 读取部署目录失败，阻断后续写盘（%s）: %v", dir, err)
			blockDir(dir)
			continue
		}
		for _, e := range entries {
			name := e.Name()
			switch {
			case strings.HasPrefix(name, ".lt-config-tmp-"):
				if rerr := os.Remove(filepath.Join(dir, name)); rerr != nil {
					log.Printf("[lt-config] 清理遗留临时文件失败，阻断后续写盘（%s）: %v", name, rerr)
					blockDir(dir)
				}
			case e.IsDir() && isValidateTempDir(name):
				if rerr := os.RemoveAll(filepath.Join(dir, name)); rerr != nil {
					log.Printf("[lt-config] 清理遗留校验目录失败，阻断后续写盘（%s）: %v", name, rerr)
					blockDir(dir)
				}
			case strings.HasSuffix(name, backupSuffix):
				if !cleanupOneBackup(dir, name) {
					blockDir(dir)
				}
			}
		}
	}
	return blocked
}

func cleanupOneBackup(dir, name string) bool {
	bak := filepath.Join(dir, name)
	target := strings.TrimSuffix(bak, backupSuffix)
	state, serr := statFileState(target)
	switch decideLeftoverBackup(state) {
	case backupRestore:
		if rerr := os.Rename(bak, target); rerr != nil {
			log.Printf("[lt-config] 恢复遗留备份失败（%s）: %v", name, rerr)
			return false
		}
		log.Printf("[lt-config] 已恢复遗留备份：%s → %s", name, target)
		return true
	case backupKeep:
		log.Printf("[lt-config] 无法判定 %s 是否存在（%v），保留备份 %s 并阻断该目录："+
			"它可能是这份配置仅存的一份", target, serr, name)
		return false
	default:
		if rerr := os.Remove(bak); rerr != nil && !os.IsNotExist(rerr) {
			log.Printf("[lt-config] 删除已失效的遗留备份失败（%s）: %v", name, rerr)
		}
		return true
	}
}
