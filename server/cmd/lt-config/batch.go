package main

import (
	"encoding/json"
	"errors"
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
	Version int `json:"version"`
	// Status 记录这一批是否已经「确认生效」。
	//
	// 没有这个字段时，只能靠「记录还在」推断「没提交完」——于是
	// 「文件都换好了、容器也重建成功了，只是记录没删掉」会被下一次启动
	// 当成未完成批次整批回滚，把一份正在运行的配置撤回。
	// 提交成功（容器已按新配置重建）后先把它改成 committed，再删记录：
	// 任何一步失败，下次启动都能分清方向。
	Status string          `json:"status,omitempty"`
	Dir    string          `json:"dir"`
	Files  []manifestEntry `json:"files"`
}

const (
	// batchStatusCommitted 表示这一批已经生效，启动时只清理、不回滚。
	batchStatusCommitted = "committed"
)

// errBatchCleanupPending 表示「文件已经回到旧配置，但批次记录或备份没清掉」。
//
// 它**不是**回滚失败：磁盘是自洽的旧版本，只是现场还留着。
// 调用方应当把它当作「已回滚」继续往下走（重建旧配置的容器），
// 同时在结果里注明现场未清理——把两者混为一谈会让管理员以为配置还是新的。
var errBatchCleanupPending = errors.New("批次现场未清理")

// errBatchRecoveryAtRisk 表示「配置已生效，但现场状态无法落定」。
//
// 具体是：容器已经按新配置启动，而批次记录既标不成 committed、也删不掉。
// 下一次启动看到这条「未提交」记录会回滚磁盘，容器却仍是新版本——这是
// 需要人介入的状态，不能只用一句 warning 带过。
var errBatchRecoveryAtRisk = errors.New("批次现场无法落定，重启可能回滚磁盘")

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

	if err := writeManifestFile(m); err != nil {
		return m, err
	}
	return m, nil
}

// writeManifestFile 把现场（含状态）覆盖写入批次记录。
func writeManifestFile(m batchManifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	// 记录里是部署目录的绝对路径，可能包含宿主机拓扑信息，按凭据文件对待。
	return writeFileAtomic(filepath.Join(m.Dir, batchManifestName), string(raw)+"\n", modeSecret)
}

// removeManifest 在整批文件已经确定落定（新配置生效或已完整回滚）后撤掉记录。
//
// 返回 false 表示记录没删掉。调用方据此决定要不要保留备份：
// 记录还在、备份却没了，下次启动就只能对着半份现场猜。
func (b *writeBatch) removeManifest(m batchManifest) bool {
	if m.Dir == "" {
		return true
	}
	if err := os.Remove(filepath.Join(m.Dir, batchManifestName)); err != nil && !os.IsNotExist(err) {
		log.Printf("[lt-config] 删除批次记录失败: %v", err)
		return false
	}
	return true
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

	if m.Status == batchStatusCommitted {
		// 这一批已经生效（文件与容器都按新配置完成），只是记录没删掉。
		// 这里**必须**只清理、不回滚：回滚会把一份正在运行的配置撤回，
		// 而它在磁盘上、容器里都已经是对的。
		log.Printf("[lt-config] 发现已提交的批次记录（%d 个文件），清理残留备份", len(m.Files))
		ok := true
		for _, f := range m.Files {
			if err := os.Remove(f.Path + backupSuffix); err != nil && !os.IsNotExist(err) {
				log.Printf("[lt-config] 清理批次备份失败（%s）: %v", f.Path, err)
				ok = false
			}
			if f.Tmp != "" {
				_ = os.Remove(f.Tmp)
			}
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[lt-config] 删除批次记录失败（%s）: %v", path, err)
			ok = false
		}
		if err := os.Remove(path + backupSuffix); err != nil && !os.IsNotExist(err) {
			ok = false
		}
		// 清理没做干净时保留记录，下次启动继续收拾；但备份已经没用了，
		// 留着也只是占空间。
		return ok
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
