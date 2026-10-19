package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	batchManifestName = ".lt-config-batch.json"

	backupSuffix = ".lt-config-bak"
)

type batchManifest struct {
	Version int             `json:"version"`
	Status  string          `json:"status,omitempty"`
	Dir     string          `json:"dir"`
	Files   []manifestEntry `json:"files"`
}

const (
	batchStatusCommitted = "committed"
)

var errBatchCleanupPending = errors.New("批次现场未清理")

var errBatchRecoveryAtRisk = errors.New("批次现场无法落定，重启可能回滚磁盘")

type manifestEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Tmp     string `json:"tmp"`
	Existed bool   `json:"existed"`

	NewSum string `json:"new_sum,omitempty"`
	BakSum string `json:"bak_sum,omitempty"`
}

func (b *writeBatch) writeManifest() (batchManifest, error) {
	m := batchManifest{Version: 1}
	for _, st := range b.staged {
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
			NewSum:  st.newSum,
			BakSum:  st.bakSum,
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

func writeManifestFile(m batchManifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.Dir, batchManifestName), string(raw)+"\n", modeSecret)
}

func (b *writeBatch) refreshBackupSums() error {
	if b.manifest.Dir == "" || len(b.manifest.Files) == 0 {
		return nil
	}
	for i := range b.manifest.Files {
		if i < len(b.staged) {
			b.manifest.Files[i].BakSum = b.staged[i].bakSum
		}
	}
	if err := writeManifestFile(b.manifest); err != nil {
		return fmt.Errorf("补写备份摘要失败: %w", err)
	}
	return nil
}

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

func batchManifestError(err error) error {
	return fmt.Errorf("写入批次记录失败（本次未改动任何文件）: %w", err)
}
