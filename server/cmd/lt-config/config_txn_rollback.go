package main

import (
	"errors"
	"fmt"
	"strings"
)

func (b *writeBatch) rollbackFailedCommit(m batchManifest, name string, cause error) error {
	if b.removeManifest(m) {
		return fmt.Errorf("替换 %s 失败，已回滚（磁盘仍为旧配置）: %w", name, cause)
	}
	return fmt.Errorf("%w: 替换 %s 失败，已回滚（磁盘仍为旧配置），但批次记录未能删除，"+
		"重启后恢复逻辑会按它把整批再回滚一次、覆盖此后的修改；请人工确认后删除部署目录下的 %s 与 *%s 备份；原始错误: %w",
		errBatchCleanupPending, name, batchManifestName, backupSuffix, cause)
}

func (b *writeBatch) finalize() error {
	if len(b.staged) == 0 {
		return nil
	}
	m := b.manifest
	m.Status = batchStatusCommitted
	if err := writeManifestFile(m); err != nil {
		if b.removeManifest(b.manifest) {
			for _, st := range b.staged {
				st.cleanupBackup()
			}
			return fmt.Errorf("批次状态未能标记，已直接清除记录（配置与容器均已生效）: %w", err)
		}
		return fmt.Errorf("%w: 批次状态未能标记、记录也未能删除，请手动删除部署目录下的 %s 与 %s 备份: %v",
			errBatchRecoveryAtRisk, batchManifestName, backupSuffix, err)
	}
	if !b.removeManifest(m) {
		return errors.New("配置已生效，但批次记录未能删除（下次启动会自动清理，不影响运行中的配置）")
	}
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	return nil
}

func (b *writeBatch) revert() error {
	modeErr := b.restoreModeFixes()
	if len(b.staged) == 0 {
		return modeErr
	}
	if err := b.rollbackCommitted(); err != nil {
		return err
	}
	if !b.removeManifest(b.manifest) {
		return fmt.Errorf("%w: 文件已恢复为旧配置，但批次记录未能删除（备份已保留，重启后会自动清理）",
			errBatchCleanupPending)
	}
	b.discard()
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	if modeErr != nil {
		return fmt.Errorf("配置已回滚为旧内容，但文件权限未能恢复: %w", modeErr)
	}
	return nil
}

func (b *writeBatch) rollbackCommitted() error {
	var failures []string
	for i := 0; i < b.done; i++ {
		if err := b.staged[i].restore(); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", b.staged[i].name, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}
