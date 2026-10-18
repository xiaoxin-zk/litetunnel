package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// 本文件是「多文件提交」的**现场记录**：格式、写入、补写摘要、删除。
//
// 进程内回滚（见 writeBatch.commit）只能覆盖「这次进程还活着」的失败。
// 强杀、断电、被容器运行时终止时，磁盘可能停在「第一个文件已换新、第二个
// 还没换」的中间态，而单看某个文件有没有备份，根本判断不出这一批到底提交
// 完没有：每个文件的备份都是独立的，齐全与否与批次是否完整无关。
//
// 所以提交前先把整批文件的身份写进一份记录。
//
// # 各部分在哪
//
//	本文件             —— 记录的格式与读写（writeManifest / 摘要补写 / 删除）
//	batch_recovery.go  —— 启动时按记录恢复，以及残留文件清理
//	config_txn.go      —— 一批文件的准备与提交
//	config_txn_rollback.go —— 一批文件的撤回与落定
//	file_commit.go     —— 单个文件的临时/备份/替换/回滚
//
// 拆开的理由：写记录与按记录恢复是**两个方向**，判据也不同（前者只看目标
// 文件在不在，后者要看备份在不在、内容对不对）。合在一起时，改动恢复那一侧
// 很容易顺手改坏写入那一侧，而写入一旦漏一次，崩溃就发生在没有记录可依的
// 窗口里。

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

// writeManifest 把本批候选文件的身份落盘，返回可交给 removeManifest 的现场。
//
// 必须在任何一个目标文件被替换**之前**完成：记录晚于替换写下的那一刻，
// 崩溃就发生在没有记录可依的窗口里。
func (b *writeBatch) writeManifest() (batchManifest, error) {
	m := batchManifest{Version: 1}
	for _, st := range b.staged {
		// 只有「确认不存在」才记 Existed=false。
		//
		// 权限不足、路径被别的进程占住、磁盘 I/O 出错时 Stat 同样返回 err，
		// 把它一并当成「文件本来就不存在」会让恢复逻辑改走「删掉新文件」那条
		// 分支：那个文件其实一直在，只是替换前没被备份成 .lt-config-bak。
		// 一旦提交后崩溃，旧内容已经无从恢复——记录还明确写着「它原本不存在」，
		// 等于把唯一能修的方向也指反了。
		//
		// 所以非 ENOENT 必须中止。此刻一个目标文件都还没动，中止是安全的。
		// 三态判定见 statcheck.go，与启动清理、批次回滚共用同一个口径。
		state, err := statFileState(st.path)
		if state == fileUnknown {
			return batchManifest{}, fmt.Errorf("检查 %s 是否存在失败（无法判断提交前是否需要备份）: %w", st.path, err)
		}
		existed := state == fileExists
		m.Files = append(m.Files, manifestEntry{
			Name:    st.name,
			Path:    st.path,
			Tmp:     st.tmp,
			Existed: existed,
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

// batchManifestError 把「写不下批次记录」这件事说清楚：
// 这种情况下一个文件都还没动，重试是安全的。
func batchManifestError(err error) error {
	return fmt.Errorf("写入批次记录失败（本次未改动任何文件）: %w", err)
}
