package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// 本文件是「配置事务」的准备与提交：候选内容先全部落到临时文件，确认无误后
// 才逐个替换目标文件（两阶段提交）。
//
// 为什么要分成两阶段：Caddyfile、frps.toml 与 .env 是**互相引用**的一组文件
// （Caddyfile 的域名要与 frps.toml 的 subDomainHost 一致，.env 的凭据要被
// Caddyfile 的 {env.X} 取到）。写成「写完一个再写下一个」，中途失败就会在
// 磁盘上留下新旧混合的配置，而它要到下一次容器重建时才以配置错误的形式爆炸。
//
// 本文件只管「准备」与「提交」；回滚与落定见 config_txn_rollback.go，
// 批次现场的读写见 batch.go，dirty scene 阻断见 config_txn_dirty.go。
// 单文件的临时文件/备份/替换细节在 envfile.go。

// pendingWrite 是一个待写入的产物。
type pendingWrite struct {
	name    string
	path    string
	content string
	mode    os.FileMode
}

// writeBatch 是一次「多文件更新」的候选集合：候选内容都已经落到临时文件，
// 但目标文件一个都还没被替换。
type writeBatch struct {
	staged  []*stagedFile
	changed map[string]bool
	warn    []string
	// done 是已成功替换的文件数，失败时用于说清边界。
	done int
	// manifest 是这一批的现场记录。commit 成功后仍保留在磁盘上，
	// 直到 finalize（确认生效）或 revert（撤回）把它撤掉。
	manifest batchManifest
}

// pendingChanges 列出「如果应用，会变化哪些文件」，全程不碰磁盘。
//
// 「保存并校验」也要给出与「应用」一致的反馈（哪些文件会变），但它的语义
// 是只读的，所以这里只比较内容。
func pendingChanges(writes []pendingWrite) []string {
	var names []string
	for _, w := range writes {
		old, err := os.ReadFile(w.path)
		if err == nil && string(old) == w.content {
			continue
		}
		names = append(names, w.name)
	}
	return names
}

// prepareWrites 比较内容、准备候选项。
//
// 内容一致的产物不准备替换，但仍会把权限纠正到期望值：早期版本给 frps.toml
// 与 .env 写过 0644，只比较内容就跳过的话，那份宽松权限会一直留在磁盘上。
// 权限被改动过会记进 warn——这不是「配置变了」，但管理员应该知道。
func prepareWrites(writes []pendingWrite) (*writeBatch, error) {
	b := &writeBatch{changed: map[string]bool{}}
	for _, w := range writes {
		if old, err := os.ReadFile(w.path); err == nil && string(old) == w.content {
			fixed, err := ensureMode(w.path, w.mode)
			if err != nil {
				b.discard()
				return nil, fmt.Errorf("检查 %s 的权限失败: %w", w.name, err)
			}
			if fixed {
				b.warn = append(b.warn,
					fmt.Sprintf("%s 的内容没变，但权限已收紧为 %#o", w.name, w.mode.Perm()))
			}
			continue
		}
		st, err := stageFile(w.name, w.path, w.content, w.mode)
		if err != nil {
			b.discard()
			return nil, fmt.Errorf("准备写入 %s 失败: %w", w.name, err)
		}
		b.staged = append(b.staged, st)
		b.changed[w.name] = true
	}
	return b, nil
}

// commit 逐个替换目标文件，失败时整体回滚。
//
// 三个文件互相引用（Caddyfile 的域名要与 frps.toml 的 subDomainHost 一致，
// .env 的凭据要被 Caddyfile 的 {env.X} 取到），必须要么全换成新的、要么全
// 保持旧的。逐个替换到一半失败就会留下新旧混合——那份配置要到下次容器重建
// 才以错误形式爆炸。所以每个文件替换前先备份旧内容（见 stagedFile.commit），
// 失败时把已替换的文件恢复，最终磁盘回到「全部旧配置」。
func (b *writeBatch) commit() error {
	// 先把整批文件的身份落盘，再动第一个目标文件。进程内回滚只覆盖「本进程
	// 还活着」的失败；强杀或断电时，磁盘可能停在第一个文件已换新、第二个
	// 还没换的中间态，而启动清理单看某个文件的备份无法判断整批是否提交完整。
	// 有这份记录，重启后就能确定「这一批没提交完」，整批回滚到旧配置。
	m, err := b.writeManifest()
	if err != nil {
		b.discard()
		return batchManifestError(err)
	}
	b.manifest = m

	for i := range b.staged {
		st := b.staged[i]
		if err := st.commit(); err != nil {
			// 当前文件替换失败（它已尽量自行恢复），回滚前面已成功替换的文件，
			// 丢弃尚未替换的临时文件。回滚本身也失败时，磁盘可能处于新旧混合
			// 状态，必须如实上报，而不是只报「替换失败」。
			rbErr := b.rollbackCommitted()
			b.discardFrom(i)
			if rbErr != nil {
				// 保留批次记录：下次启动时由它把整批恢复回去。删掉记录等于
				// 把「磁盘可能混合」这件事藏起来。
				return fmt.Errorf("替换 %s 失败，且回滚未完成（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", st.name, err, rbErr)
			}
			return b.rollbackFailedCommit(m, st.name, err)
		}
		b.done++
	}
	// 每个文件的备份摘要此刻才齐全，补写进记录：崩溃恢复时要靠它确认
	// 「这份备份确实是当时的旧文件」，而不是一份写了一半的东西。
	b.refreshBackupSums()

	// 全部成功，但**不在这里**撤记录、清备份。
	//
	// 配置是否真的生效要等容器重建完——那一步由调用方做（见 apply 的
	// finalize 调用）。在这里清掉备份，容器重建失败时就再也回不去旧配置；
	// 而在这里清掉记录，「文件已换好、容器没起来」的中间态就少了一份说明。
	return nil
}

// commitFailure 把 writeBatch.commit 的失败翻译成调用方该做的事。
//
// 单独抽出来的理由：`errBatchCleanupPending` 不是「写盘失败」而是「磁盘已经
// 回到旧配置、现场却还留着」，两者的处理方式完全不同——前者管理员改配置
// 重试即可，后者必须人工清理，而且在那之前本进程不能再写盘，否则会与那份
// 未清理的记录互相覆盖（下次启动它会按记录把整批再回滚一遍，管理员这期间
// 手工改好的内容会被当成要撤掉的现场）。
//
// 因此这里与 finalize 分支的 errBatchRecoveryAtRisk 保持一致：登记运行时
// 阻断 + 报 partial（附各容器状态），而不是草草地包成 internalError。
func (s *service) commitFailure(err error) error {
	if !errors.Is(err, errBatchCleanupPending) {
		return internalError(err)
	}
	s.registerDirtyScene()
	statesCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return &partialApplyError{
		msg: fmt.Sprintf("本次写盘已回滚（磁盘仍为旧配置），但批次现场未能清理："+
			"重启后恢复逻辑会按残留记录把整批再回滚一次、覆盖此后的任何修改；"+
			"在人工清理之前，所有写操作都会被拒绝\n%v", err),
		services: s.serviceStates(statesCtx),
		cause:    err,
	}
}

// discard 放弃整批候选内容。
func (b *writeBatch) discard() { b.discardFrom(0) }

func (b *writeBatch) discardFrom(i int) {
	for _, st := range b.staged[i:] {
		st.discard()
	}
}
