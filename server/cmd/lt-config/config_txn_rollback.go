package main

import (
	"errors"
	"fmt"
	"strings"
)

// 本文件是配置事务的收尾：提交后的整体回滚（revert）、确定生效后的落定
// （finalize），以及「替换失败但已回滚成功」那条路径（rollbackFailedCommit）。
//
// 为什么单独成文：这几种结局对磁盘与批次现场的处置完全不同，判据却共用同一份
// manifest 与备份（记录删不删得掉、备份要不要留），放在一起才不容易被改坏。
// 提交与候选准备见 config_txn.go，批次现场的读写见 batch.go。

// rollbackFailedCommit 收尾「替换失败、但已回滚成功」这条路径。
//
// 回滚成功不等于现场干净：批次记录还在磁盘上时，它会成为下一次启动的
// 权威依据——那份记录写的是「这一批没提交完」，恢复逻辑会按它把整批再
// 回滚一遍。管理员随后手工改好的内容会被当成要撤掉的现场，而备份已在本次
// 回滚中消耗掉，那次回滚只能按记录硬删文件。所以记录删不掉时**必须**返回
// 能被 errors.Is(err, errBatchCleanupPending) 识别的错误，交给调用方登记
// 运行时阻断；静默忽略（丢弃 removeManifest 的返回值）是最糟的做法。
//
// 单独抽成方法是为了让这条路径可以被单元测试直接覆盖：制造一次
// 「替换失败 + 记录删不掉」需要先占住 .lt-config-batch.json，测试里能构造，
// 但写在 commit 内部就只能靠整个 renderAndApply 流程间接观察。
func (b *writeBatch) rollbackFailedCommit(m batchManifest, name string, cause error) error {
	if b.removeManifest(m) {
		return fmt.Errorf("替换 %s 失败，已回滚（磁盘仍为旧配置）: %w", name, cause)
	}
	// 两个 %w 是有意的：调用方既要能 errors.Is 认出 errBatchCleanupPending
	// （据此登记运行时阻断），又要能追溯最初的替换失败原因。
	return fmt.Errorf("%w: 替换 %s 失败，已回滚（磁盘仍为旧配置），但批次记录未能删除，"+
		"重启后恢复逻辑会按它把整批再回滚一次、覆盖此后的修改；请人工确认后删除部署目录下的 %s 与 *%s 备份；原始错误: %w",
		errBatchCleanupPending, name, batchManifestName, backupSuffix, cause)
}

// finalize 在配置确认生效（容器已按新配置重建）后落定这一批。
//
// 顺序：先标记 committed，再删记录，最后清备份。
//   - 标记失败 → 保留记录与备份。下次启动看到的是「未提交」，会回滚——
//     这会把一份已经生效的配置撤回，但比「磁盘与容器都在新版本、记录却
//     指向不存在的备份」更容易收拾；
//   - 记录删失败 → 记录仍是 committed，下次启动只清理、不回滚
//     （见 recoverBatch），备份留到那时再清；
//   - 备份清理失败 → 只是残留文件，不影响任何判定。
func (b *writeBatch) finalize() error {
	if len(b.staged) == 0 {
		return nil
	}
	m := b.manifest
	m.Status = batchStatusCommitted
	if err := writeManifestFile(m); err != nil {
		// 标记写不进去（磁盘满、目录权限被改）。这时**不能**把记录留在
		// 「未提交」状态：容器已经按新配置跑起来了，下次启动按记录回滚
		// 会把磁盘退回旧配置，而容器仍是新版本——磁盘与容器分叉。
		//
		// 退而删除记录：删除比写入更可能成功（不需要新空间），而
		// 「没有记录」正是启动恢复理解的「已落定」。
		if b.removeManifest(b.manifest) {
			for _, st := range b.staged {
				st.cleanupBackup()
			}
			return fmt.Errorf("批次状态未能标记，已直接清除记录（配置与容器均已生效）: %w", err)
		}
		// 标记与删除都失败：只能如实告知。清理备份会把最后一点现场也抹掉，
		// 所以保留它们，留给人工判断。
		return fmt.Errorf("%w: 批次状态未能标记、记录也未能删除，请手动删除部署目录下的 %s 与 %s 备份: %v",
			errBatchRecoveryAtRisk, batchManifestName, backupSuffix, err)
	}
	if !b.removeManifest(m) {
		// 记录已经标成 committed，留着无害；备份也留着，等下次启动清理。
		return errors.New("配置已生效，但批次记录未能删除（下次启动会自动清理，不影响运行中的配置）")
	}
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	return nil
}

// revert 把整批文件恢复成提交前的旧内容，并撤掉记录与备份。
//
// 用于「文件已经换好，但容器重建失败」：此时磁盘是新配置、容器还是旧的，
// 不做这一步就留下一个跨版本的半成品。
func (b *writeBatch) revert() error {
	if len(b.staged) == 0 {
		return nil
	}
	if err := b.rollbackCommitted(); err != nil {
		// 恢复失败：记录与备份必须留着，它们是下次启动唯一能依的现场。
		return err
	}
	if !b.removeManifest(b.manifest) {
		// 文件已经回到旧配置，但记录还在。此时**不能**清备份：
		// 下次启动会看到这份「未提交」记录，再回滚一遍——如果那次发现
		// 某个文件仍停在中间态（例如 restore 之后又被别的东西写过），
		// 备份就是唯一的材料。清掉它等于把「还能修」变成「只能手工拼」。
		//
		// 回滚本身是成功的，所以返回哨兵错误而不是普通错误：调用方要
		// 继续按旧配置重建容器，只是别把这次操作报成「磁盘还是新配置」。
		return fmt.Errorf("%w: 文件已恢复为旧配置，但批次记录未能删除（备份已保留，重启后会自动清理）",
			errBatchCleanupPending)
	}
	b.discard()
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	return nil
}

// rollbackCommitted 把已成功替换的文件恢复到备份的旧内容，返回恢复过程中
// 收集到的所有错误（nil 表示全部恢复成功）。
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
