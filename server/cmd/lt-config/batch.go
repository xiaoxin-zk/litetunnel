package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// NewSum / BakSum 是候选内容与备份内容的 sha256（十六进制）。
	//
	// 恢复时不能只看「备份在不在」：备份存在只说明动过这个文件，而
	// 「目标内容等于候选」才是替换发生过的硬证据。少了这个判据，
	// 「替换已完成、备份却丢了」会被当成「还没开始替换」，于是新内容
	// 被留在磁盘上、恢复记录还被删掉——半套配置再也无人知晓。
	//
	// 旧版本写下的记录没有这两个字段（空串），恢复时自动跳过校验，
	// 退回原有判据，不会因为升级而无法恢复。
	NewSum string `json:"new_sum,omitempty"`
	BakSum string `json:"bak_sum,omitempty"`
}

// contentSum 返回内容的 sha256 十六进制表示。
func contentSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// fileSum 返回文件内容的 sha256 十六进制表示。
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
			// BakSum 此刻还是空的（备份尚未创建），由 refreshBackupSums
			// 在整批替换完成后补写一次。
			NewSum: st.newSum,
			BakSum: st.bakSum,
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

// refreshBackupSums 把备份摘要补写进批次记录。
//
// 摘要只有在每个文件真正完成备份之后才算得出来，而记录必须在第一次替换
// **之前**就落盘（否则崩溃时没有记录可依）。所以这里多写一次。
//
// 补写失败不影响本批的推进：记录里少一层校验，恢复退回「备份是否存在」
// 的老判据，与升级前的行为一致。真正危险的是「记录写着摘要、备份却不是
// 那份内容」，那是恢复时的校验负责挡住的事。
func (b *writeBatch) refreshBackupSums() {
	if b.manifest.Dir == "" || len(b.manifest.Files) == 0 {
		return
	}
	for i := range b.manifest.Files {
		if i < len(b.staged) {
			b.manifest.Files[i].BakSum = b.staged[i].bakSum
		}
	}
	if err := writeManifestFile(b.manifest); err != nil {
		log.Printf("[lt-config] 补写备份摘要失败（恢复时退回备份存在性判断）: %v", err)
	}
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
		// 记录本身读不懂时绝不能猜，更不能删除：它可能仍是多文件恢复现场
		// 的唯一索引。退回单文件清理会删掉备份或留下新旧混合配置，之后再也
		// 无法判断哪些文件属于同一批。保留原文件、备份和目标，让调用方进入
		// 人工阻断状态。
		log.Printf("[lt-config] 批次记录无法解析（%s），保留现场并阻断后续写盘: %v", path, err)
		return false
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
			// 备份存在 = 这个文件的替换进行过。先用记录里的摘要确认备份
			// 确实是当时那份旧文件：写了一半、被别的进程覆盖、卷映射错位
			// 都会让「备份文件在」与「备份内容对」不一致，拿坏备份覆盖
			// 等于把一份损坏的配置扶正，比不动更糟。
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
		}
		// 没有备份时先看目标内容是不是**候选内容**。
		//
		// 若是，说明替换已经发生、而备份已经不在了——旧内容无从恢复。
		// 旧实现会把它当成「还没进入替换」放过，于是新内容留在磁盘上、
		// 记录随后被删掉，半套配置再也无人知晓。这里必须报失败并保留现场。
		if f.NewSum != "" {
			if sum, err := fileSum(f.Path); err == nil && sum == f.NewSum {
				log.Printf("[lt-config] 批次回滚：%s 已是新内容但没有备份可用于恢复", f.Name)
				failed = append(failed, f.Name)
				continue
			}
		}
		// 其余情况只有两种：这个文件还没进入替换（旧内容还在，不必动），
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

	// 删记录之前再核对一遍内容：上面的循环只保证 rename 返回成功，
	// 而「rename 成功了」不等于「文件里就是那份旧内容」（备份可能来自
	// 另一份副本，或文件系统把写入落到了别处）。日志摘要可用的文件，
	// 此刻必须是旧内容，否则保留现场，别把「看起来回滚了」当成回滚完成。
	for _, f := range m.Files {
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
