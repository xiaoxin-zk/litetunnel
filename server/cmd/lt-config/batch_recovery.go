package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// 本文件是启动时的**恢复**单元：按批次记录把整批文件回滚到提交前状态，
// 再清理上次异常退出留下的临时文件与备份。
//
// # 为什么单独拆出来
//
// 这里做的每一个动作都**不可撤回**，而且判断依据往往已经不完整（进程被强杀、
// 断电，磁盘上只剩记录与备份）。因此它与「正常提交」必须分开看：
//
//	本文件             —— 只在启动时跑，判据是「记录与备份能不能对上」
//	batch.go           —— 记录的格式与读写，判据是「目标文件在不在」
//	config_txn.go      —— 正常路径的准备与提交
//	config_txn_rollback.go —— 正常路径的撤回与落定
//	file_commit.go     —— 单个文件的临时/备份/替换/回滚
//	statcheck.go       —— 「路径在不在」的三态判定
//
// 合并在一起时最危险的改法是「让恢复复用正常路径的重试逻辑」——正常路径失败
// 可以再试一次，而恢复的全部意义是**这一次就把磁盘定下来**，重试只会让判断
// 依据越来越少。
//
// # 一条贯穿全文的规则
//
// 任何「判不出来」都必须按「还没确定」处理：保留记录与备份、返回 false，
// 让调用方登记运行时阻断。猜错的方向只有两个，两个都会造成不可挽回的后果：
// 猜「已落定」会删掉唯一能修复磁盘的现场，猜「已回滚」会把一份新内容留在
// 磁盘上还删掉记录。

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
	failed := rollbackEntries(m.Files)
	for _, f := range m.Files {
		if f.Tmp != "" {
			_ = os.Remove(f.Tmp)
		}
	}

	// 删记录之前再核对一遍内容：rollbackEntries 只保证 rename 返回成功，
	// 而「rename 成功了」不等于「文件里就是那份旧内容」（备份可能来自
	// 另一份副本，或文件系统把写入落到了别处）。日志摘要可用的文件，
	// 此刻必须是旧内容，否则保留现场，别把「看起来回滚了」当成回滚完成。
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

// rollbackEntries 逐个文件尝试恢复到提交前的状态，返回失败的条目名。
//
// 每个文件的处置分三支（判定在 statcheck.go）：
//
//   - 备份确认存在 → 核对摘要后用它恢复（「替换进行过」的硬证据）；
//   - 备份确认不存在 → 再核对目标内容：若已是候选内容，说明替换发生过而
//     备份丢了，旧内容无从恢复，必须报失败；否则要么「还没进入替换」
//     （不动），要么「原本不存在而现在多了个新文件」（删掉）；
//   - 备份判不出来 → 什么都不做，记成失败，保留现场等人工确认。
//
// 返回的失败清单会阻止记录被删除，这是整套恢复的核心安全性质。
func rollbackEntries(files []manifestEntry) []string {
	var failed []string
	for _, f := range files {
		bak := f.Path + backupSuffix
		// 三分支，判定在 statcheck.go：只有「确认存在」才按备份恢复，
		// 只有「确认不存在」才往下走「目标是不是已经是新内容」的核对，
		// 「判不出来」必须保留现场。
		//
		// 这里曾经是 `if _, err := os.Stat(bak); err == nil { 恢复 }`：非 ENOENT
		// 的 Stat 失败会掉进「没有备份」那条路，而那条路最终可能把记录当已
		// 落定删掉——一份读不出备份的现场就此消失，磁盘停在新旧混合状态。
		bakState, serr := statFileState(bak)
		switch decideBatchBackup(bakState) {
		case recoveryFromBackup:
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
		case recoveryKeep:
			// 判不出备份在不在：既不能按「有备份」把记录里的内容扶正，
			// 也不能按「没备份」把这一批当已落定。记成失败，于是记录与
			// 备份全部保留，调用方据此阻断写盘，等人工确认。
			log.Printf("[lt-config] 批次回滚：无法判定备份是否存在（%s）: %v；保留记录与备份，等待人工确认",
				bak, serr)
			failed = append(failed, f.Name)
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
	return failed
}

// verifyRollback 在删记录之前按摘要核对回滚结果，返回失败的条目名。
//
// 摘要为空（旧版本写下的记录）时跳过：没有比对依据，硬要比只会让升级阻断
// 一批本来能恢复的现场。
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

// cleanupLeftovers 启动时清理上次异常退出留下的现场。
//
// 三类残留处理方式不同：
//
//   - .lt-config-batch.json 是未完成的批次记录：先按它把整批文件回滚，
//     再走下面的单文件规则（见 recoverBatch）；
//   - .lt-config-tmp-* 是尚未提交的候选内容，谁都没引用，直接删；
//   - *.lt-config-bak 是提交时给旧文件做的备份：目标文件**确认存在**（说明
//     新文件已落位、备份是旧的）就删掉；目标文件**确认缺失**（崩溃发生在
//     「旧文件改名成备份、新文件还没落位」之间）就把备份恢复回原位——否则
//     活动配置就凭空消失了；**判不出来**（Stat 返回非 ENOENT 的错误：权限
//     不足、路径被占用、I/O 出错）时两者都不做，原样保留并阻断这个目录。
//     第三种情况是这条规则里唯一的新增分支，也是唯一不能猜的地方：猜错一边
//     会删掉这份配置仅存的一份，另一边会用旧内容顶掉正在生效的那份。
//   - .lt-config-caddy-* / .lt-config-frps-* 是校验用的临时目录，里面放着
//     挂进容器的凭据 env 文件，必须整目录删掉。
//
// 必须在 validateConfig 之前调用：崩溃可能把 .env 也留成「缺失 + 备份」的
// 状态，不先恢复的话启动校验会直接报「缺少 .env」。
//
// 返回值是**没能自动收敛**的目录。它们被原样保留（记录、备份、目标都在），
// 调用方必须据此拒绝后续的写盘操作：再应用一次会覆盖掉唯一可恢复的现场，
// 把「还能修」变成「只能人工拼」。这类目录只应由人看过之后手工清理。
func cleanupLeftovers(p paths) []string {
	var blocked []string
	// 同一个目录可能被多种原因反复登记（批次回滚未完成、备份判不出来、
	// 恢复失败），去重一次：blockedDirs 会原样进健康响应，重复项会让
	// 管理员以为存在多个现场。
	blockDir := func(dir string) {
		for _, existing := range blocked {
			if existing == dir {
				return
			}
		}
		blocked = append(blocked, dir)
	}
	seen := map[string]bool{}
	for _, f := range []string{p.caddyOut, p.frpsOut, p.envFile} {
		dir := filepath.Dir(f)
		if seen[dir] {
			continue
		}
		seen[dir] = true

		// 有未完成的批次记录时先按批次整体回滚。单文件备份只能说明「这个
		// 文件被替换过」，说明不了整批是否提交完整——那正是强杀/断电之后
		// 最危险的中间态。
		//
		// 回滚没能完成时**跳过**这个目录的单文件清理：那些备份正是下一次
		// 恢复的依据，按单文件规则处理（目标在就删备份）会把唯一的退路
		// 删掉，磁盘从此停在新旧混合状态，再无自动修复的机会。
		if !recoverBatch(dir) {
			log.Printf("[lt-config] %s 的批次回滚未完成，跳过本次残留清理", dir)
			blockDir(dir)
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			// 读不出目录内容就无法判断有没有遗留备份。**什么都不做**是这里
			// 最安全的选择：一个文件都不会被删（不是删一半），只是这次清理
			// 没发生。留一条日志，否则「为什么备份还在」没有任何线索。
			log.Printf("[lt-config] 读取部署目录失败，跳过本次残留清理（%s）: %v", dir, err)
			continue
		}
		for _, e := range entries {
			name := e.Name()
			switch {
			case strings.HasPrefix(name, ".lt-config-tmp-"):
				if rerr := os.Remove(filepath.Join(dir, name)); rerr != nil {
					log.Printf("[lt-config] 清理遗留临时文件失败（%s）: %v", name, rerr)
				}
			case e.IsDir() && isValidateTempDir(name):
				// 校验用的临时目录里有挂进容器的 env 文件（DNS 凭据）。
				// 只清普通临时文件的话，异常退出后这些凭据会一直留在部署
				// 目录里——而那是个能被备份、被同步、被随手打包带走的地方。
				if rerr := os.RemoveAll(filepath.Join(dir, name)); rerr != nil {
					log.Printf("[lt-config] 清理遗留校验目录失败（%s）: %v", name, rerr)
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

// cleanupOneBackup 处理一个遗留的 *.lt-config-bak，返回是否「确定落定」。
//
// 返回 false 表示判不出来（或恢复失败），调用方必须把这个目录登记成阻断。
// 摘成独立函数是为了让三分支各自短到可以一眼看清——这段逻辑的代价是「删掉
// 活动配置的唯一副本」，不适合塞在两层循环里。
func cleanupOneBackup(dir, name string) bool {
	bak := filepath.Join(dir, name)
	target := strings.TrimSuffix(bak, backupSuffix)
	// 三分支，判定在 statcheck.go：只有「确认存在」才允许删备份，
	// 只有「确认不存在」才允许把备份放回去，「判不出来」必须原样
	// 留着并进入阻断。
	//
	// 这里曾经是 `if os.IsNotExist(err) { 恢复 } else { 删备份 }`：
	// 权限不足、路径被占用、I/O 出错时 Stat 同样返回 err，但那种
	// err 不是 ENOENT——它被这个 else 读成「目标在，备份是旧的」，
	// 于是删掉了活动配置的**唯一**副本。磁盘从此停在新旧混合状态，
	// 而「还能自动修」变成了「只能人工拼」。
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
		// 目标确实在：备份只是替换前留下的旧内容。删除也失败时
		// 没有风险（多一个残留文件而已），不值得阻断，留一条日志。
		if rerr := os.Remove(bak); rerr != nil && !os.IsNotExist(rerr) {
			log.Printf("[lt-config] 删除已失效的遗留备份失败（%s）: %v", name, rerr)
		}
		return true
	}
}
