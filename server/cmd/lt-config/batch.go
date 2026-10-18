package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// 本文件负责「多文件提交」的现场记录与崩溃恢复。
//
// 进程内回滚（见 writeBatch.commit）只能覆盖「这次进程还活着」的失败。
// 强杀、断电、被容器运行时终止时，磁盘可能停在「第一个文件已换新、第二个
// 还没换」的中间态，而单看某个文件有没有备份，根本判断不出这一批到底提交
// 完没有：每个文件的备份都是独立的，齐全与否与批次是否完整无关。
//
// 所以提交前先把整批文件的身份写进一份记录，恢复时按批次整体回滚。

const (
	// batchManifestName 是批次记录的固定文件名，与批次文件同目录。
	batchManifestName = ".lt-config-batch.json"

	// backupSuffix 是替换前旧文件的备份后缀。
	backupSuffix = ".lt-config-bak"
)

// batchManifest 是一次多文件提交的现场。
type batchManifest struct {
	Version int             `json:"version"`
	Dir     string          `json:"dir"`
	Files   []manifestEntry `json:"files"`
}

// manifestEntry 记录一个文件在提交前的状态。
type manifestEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// Tmp 是候选内容的临时路径：崩溃后残留的临时文件也由这里定位。
	Tmp string `json:"tmp"`
	// Existed 表示目标文件在提交前是否存在。原本不存在的文件，回滚是
	// 「删掉新文件」而不是「放回备份」。
	Existed bool `json:"existed"`
}

// writeManifest 把本批候选文件的身份落盘，返回可交给 removeManifest 的现场。
//
// 必须在任何一个目标文件被替换**之前**完成：记录晚于替换写下的那一刻，
// 崩溃就发生在没有记录可依的窗口里。
func (b *writeBatch) writeManifest() (batchManifest, error) {
	m := batchManifest{Version: 1}
	for _, st := range b.staged {
		_, err := os.Stat(st.path)
		m.Files = append(m.Files, manifestEntry{
			Name:    st.name,
			Path:    st.path,
			Tmp:     st.tmp,
			Existed: err == nil,
		})
	}
	if len(m.Files) == 0 {
		return m, nil
	}
	m.Dir = filepath.Dir(m.Files[0].Path)

	raw, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	// 记录里是部署目录的绝对路径，可能包含宿主机拓扑信息，按凭据文件对待。
	if err := writeFileAtomic(filepath.Join(m.Dir, batchManifestName), string(raw)+"\n", modeSecret); err != nil {
		return m, err
	}
	return m, nil
}

// removeManifest 在整批文件已经确定落定（新配置生效或已完整回滚）后撤掉记录。
func (b *writeBatch) removeManifest(m batchManifest) {
	if m.Dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(m.Dir, batchManifestName)); err != nil && !os.IsNotExist(err) {
		log.Printf("[lt-config] 删除批次记录失败: %v", err)
	}
}

// recoverBatch 按批次记录把整批文件恢复到提交前状态，返回是否已经「确定落定」。
//
// 判据只有一条：备份文件存在，说明那个文件的替换已经进行过。
// 恢复方式是「先删目标再放回备份」——Windows 上 Rename 到已存在的文件会
// 直接失败，不先删就恢复不了，而这一步恰恰发生在最需要它的时候。
//
// 全部替换成功、只剩记录与备份没清时崩溃，这里同样会把整批回滚到旧配置。
// 这是刻意的：那种状态下无法确认容器是否已经按新配置重建过，宁可回到
// 一份确定一致的旧配置，再由管理员重新应用一次。
//
// 返回 false 表示**至少有一个文件没能恢复**。此时绝不能删记录与备份：
// 它们是下一次尝试恢复的唯一依据，而磁盘正处在「新旧混合」状态——
// 删掉就等于把「还能修」变成「只能人工拼」。
func recoverBatch(dir string) bool {
	path := filepath.Join(dir, batchManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[lt-config] 读取批次记录失败（%s）: %v", path, err)
			// 读不出来（权限、被占用）同样是「还没确定」，不能继续清理。
			return false
		}
		// 没有记录：上一批已经落定，按单文件规则清理即可。
		return true
	}

	var m batchManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		// 记录本身读不懂时不能猜：删掉它，退回单文件规则清理，
		// 至少保证下次启动不会一直卡在这份坏记录上。
		log.Printf("[lt-config] 批次记录无法解析（%s），改按单文件规则清理: %v", path, err)
		_ = os.Remove(path)
		return true
	}

	log.Printf("[lt-config] 发现未完成的批次提交（%d 个文件），按批次整体回滚", len(m.Files))
	var failed []string
	for _, f := range m.Files {
		bak := f.Path + backupSuffix
		if _, err := os.Stat(bak); err == nil {
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
		}
		// 没有备份只有两种可能：这个文件还没进入替换（旧内容还在，不必动），
		// 或者它原本不存在而现在多了一个新文件（必须删掉，否则就是半套配置）。
		if !f.Existed {
			if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 批次回滚：删除多余文件失败（%s）: %v", f.Path, err)
				failed = append(failed, f.Name)
			}
		}
	}
	for _, f := range m.Files {
		if f.Tmp != "" {
			_ = os.Remove(f.Tmp)
		}
	}

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

// batchManifestError 把「写不下批次记录」这件事说清楚：
// 这种情况下一个文件都还没动，重试是安全的。
func batchManifestError(err error) error {
	return fmt.Errorf("写入批次记录失败（本次未改动任何文件）: %w", err)
}
