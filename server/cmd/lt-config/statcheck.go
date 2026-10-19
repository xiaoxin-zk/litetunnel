package main

import "os"

// 本文件是「路径在不在」的**唯一**判定口径，以及两处启动清理据此做出的决定。
//
// 为什么值得单独成文：os.Stat 返回 err 其实有两种完全不同的含义，而
// `if err != nil` 把它们写成了一行。
//
//   - ENOENT：路径确实不存在。这是「本来就没有旧文件」的唯一合法证据；
//   - 其余（权限不足、中间路径是个文件、卷没挂上、I/O 出错……）：判不出来。
//     它既不是「在」，也不是「不在」，而是一个**未知**。
//
// 早期实现把两者合成「在或不在」（`if _, err := os.Stat(p); err == nil`），
// 于是「判不出来」被读成「不在」：备份不写、遗留备份被删掉、目标文件被当成
// 多余文件删掉——这些动作全都不可撤回。而部署目录里唯一还能修复磁盘的东西
// 就是那些备份，被一次误判删掉之后，磁盘就永久停在新旧混合状态，再没有任何
// 自动修复的可能。
//
// 所以这里只回答三态（在 / 不在 / 判不出来），由调用方分别处置；「判不出来」
// 一律保留现场并交给运行时阻断，等人来看。判定本身刻意做成纯函数，这样
// 三分支都能被单测直接覆盖——真实的非 ENOENT 错误很难在测试里稳定构造
// （Windows 上尤其难，见 stat_semantics_test.go 的说明）。

// fileState 是「目标路径在不在」的判定结果。
type fileState int

const (
	// fileMissing 表示确认不存在（ENOENT）。只有它允许说「本来就没有」。
	fileMissing fileState = iota
	// fileExists 表示确认存在。
	fileExists
	// fileUnknown 表示判不出来（非 ENOENT 的 Stat 失败）。
	//
	// 任何据此推断「文件不在」的动作都必须停下：那不是观察到的结论，
	// 而是猜的，而猜错的代价是删掉唯一可恢复的那份内容。
	fileUnknown
	// fileNotRegular 表示路径存在，但不是普通文件（目录、设备、管道……）。
	//
	// 只由 statRegularFileState 返回：它检查的是「这是一个**文件**」，
	// 而不是「这里有个东西」。路径被替换成目录时，os.Stat 会成功（fileExists），
	// 但随后的渲染/读文件必然失败——健康检查与启动校验若只看存在性，就会
	// 通过校验、等写盘/渲染才崩，还把原因报成与真实情况无关。
	fileNotRegular
)

// statFileState 把 os.Stat 的结果归成三态。
//
// 返回的 error 只在 fileUnknown 时非 nil，供调用方写日志时带上原始原因；
// fileMissing 不是错误，ENOENT 恰恰是「确认不存在」这个结论本身。
func statFileState(path string) (fileState, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fileMissing, nil
		}
		return fileUnknown, err
	}
	return fileExists, nil
}

// statRegularFileState 与 statFileState 相同，但额外要求目标是普通文件。
//
// 用于「这里必须是文件」的路径（模板、.env、compose）：路径被替换成目录时，
// 存在性检查会放过它，而实际渲染/读取才失败。单独一个函数而不是改
// statFileState，是因为后者还被用来判目录（证书目录），不能全局要求普通文件。
func statRegularFileState(path string) (fileState, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileMissing, nil
		}
		return fileUnknown, err
	}
	if !info.Mode().IsRegular() {
		return fileNotRegular, nil
	}
	return fileExists, nil
}

// backupAction 说明「启动清理遇到一个 *.lt-config-bak 时该怎么做」。
type backupAction int

const (
	// backupRestore：目标缺失。备份是这份活动配置的**唯一**副本，放回原位。
	backupRestore backupAction = iota
	// backupDrop：目标在。备份是替换前留下的旧内容，删掉。
	backupDrop
	// backupKeep：判不出来。既不能放回（目标可能好端端地在那儿，覆盖它
	// 等于用旧配置顶掉正在生效的那份），也不能删（目标可能真的缺了，
	// 删掉之后活动配置就凭空消失）。保留现场，交给运行时阻断。
	backupKeep
)

// decideLeftoverBackup 把「遗留备份怎么处理」的判定从执行里摘出来。
//
// 摘出来的唯一理由是**可测**：真实的 Stat 失败在测试里不好构造，而这条
// 判定一旦写错就是删掉活动配置的最后一份副本，必须能被逐支覆盖。
func decideLeftoverBackup(state fileState) backupAction {
	switch state {
	case fileExists:
		return backupDrop
	case fileUnknown:
		return backupKeep
	default:
		return backupRestore
	}
}

// recoveryAction 说明「批次回滚遇到某个文件的备份时该怎么做」。
type recoveryAction int

const (
	// recoveryFromBackup：备份在，说明这个文件的替换进行过，按记录里的摘要
	// 核对后用它恢复旧内容。
	recoveryFromBackup recoveryAction = iota
	// recoveryCheckTarget：备份确实不存在。不能直接当成「还没进入替换」——
	// 目标可能已经是候选内容而备份丢了，那种情况没有旧内容可恢复。
	recoveryCheckTarget
	// recoveryKeep：判不出备份在不在。下面两条路都会做出无法撤回的结论
	// （按「有备份」把记录里的内容扶正，或按「没备份」把记录当已落定删掉），
	// 所以保留现场：记录与备份都留着，由人工确认。
	recoveryKeep
)

// decideBatchBackup 把「批次回滚时备份在不在」的判定从执行里摘出来，理由同上。
func decideBatchBackup(state fileState) recoveryAction {
	switch state {
	case fileExists:
		return recoveryFromBackup
	case fileUnknown:
		return recoveryKeep
	default:
		return recoveryCheckTarget
	}
}
