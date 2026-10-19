package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// 本文件是**单个文件**的提交单元：先把候选内容落到同目录临时文件，再原子替换
// 目标路径，替换前把旧文件改名成备份（失败时用它回滚）。
//
// # 为什么单独拆出来
//
// 这是整套写盘流程里唯一会「改活动文件」的地方，也是唯一需要备份的地方。
// 它的正确性只依赖三件事：备份是否真的做了（existed 判定）、替换失败时能不能
// 放回去（restore）、以及目录项有没有落盘（syncDirBestEffort）。这三件事与
// 「一批文件怎么协同」无关——那是 config_txn.go 的事。
//
// 拆开之后，读这段代码的人不必同时想着批次记录与 dirty scene：
//
//	本文件             —— 一个文件：临时 → 备份 → 替换 → 回滚
//	config_txn.go      —— 一批文件：准备、提交、失败翻译
//	config_txn_rollback.go —— 一批文件：撤回、落定
//	batch.go           —— 一批文件的崩溃现场：记录与恢复
//	envfile.go         —— .env 的读改写与产物权限
//	dotenv.go          —— .env 一行的语义
//
// 错误语义与拆之前**逐字一致**：替换失败且恢复成功时返回裸 err（调用方据此
// 判断「磁盘还是旧配置」），恢复也失败时把两个错误一起报出去。

// stagedFile 是一个已经落到临时文件、但尚未替换到目标路径的产物。
//
// 为什么要有这一层：Caddyfile、frps.toml 与 .env 是**互相引用**的一组文件
// （Caddyfile 里的域名要与 frps.toml 的 subDomainHost 一致，.env 里的凭据
// 要被 Caddyfile 的 {env.X} 取到）。写成「写完一个再写下一个」的话，中途
// 失败会在磁盘上留下新旧混合的状态，而它要到下一次容器重建时才以配置错误
// 的形式暴露出来。两阶段的做法是：候选内容全部准备好之后，再逐个替换。
type stagedFile struct {
	name string
	path string
	tmp  string
	// backup 是替换前旧文件的备份路径；替换成功后删除，失败时用于回滚。
	backup string
	// existed 记录目标路径在替换前是否已存在。原本不存在的文件，回滚时
	// 不是「把备份放回去」，而是「把刚创建的新文件删掉」——否则会留下
	// 半套配置（新文件在、旧文件从来没有）。
	existed bool

	// newSum 是候选内容的 sha256（十六进制）。
	//
	// 崩溃恢复时它比「备份文件在不在」更硬：备份存在只说明动过这个文件，
	// 而目标内容与候选一致，才证明替换**确实已经发生**。两者结合可以区分
	// 「还没进入替换」和「替换完成但备份丢了」——后者不能当成前者处理，
	// 否则会把一份新内容留在磁盘上、还把恢复记录删掉。
	newSum string
	// bakSum 是备份内容的 sha256（十六进制），替换前算好。
	// 读不出来时留空：恢复退回旧判据，而不是让整次应用失败。
	bakSum string
}

// stageFile 把内容写进同目录的临时文件并设好权限，内容尚未生效。
func stageFile(name, path, content string, mode os.FileMode) (*stagedFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".lt-config-tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	st := &stagedFile{name: name, path: path, tmp: tmp, newSum: contentSum(content)}

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		st.discard()
		return nil, err
	}
	if err := f.Close(); err != nil {
		st.discard()
		return nil, err
	}
	return st, nil
}

// commit 把候选内容原子替换到目标路径，替换前先把旧文件备份下来。
//
// 替换失败时自行恢复旧文件，返回错误。备份是回滚的关键：三个文件互相引用，
// 逐个替换时若第二个失败、第一个已生效，磁盘上就是新旧混合的配置——那份
// 状态要到下次容器重建才以配置错误的形式爆炸。有备份就能在失败时整体回滚。
func (s *stagedFile) commit() error {
	// 备份旧文件（若存在）。用 rename：原子且不跨文件系统（备份与目标同目录）。
	//
	// 「存在」只能由 ENOENT 来否定。权限不足、路径被占用、I/O 错误这些
	// 非 ENOENT 的失败如果被当成「本来就没有旧文件」，existed 会被记成
	// false、备份也不会创建：替换之后崩溃，restore 走的是「删掉新文件」，
	// 而那个位置原本有一份正常配置——一次写盘就把活动配置写没了。
	// 所以非 ENOENT 直接中止：候选内容还在临时文件里，目标文件一个字节没动。
	//
	// 三态判定见 statcheck.go，与启动清理、批次回滚共用同一个口径。
	state, err := statFileState(s.path)
	if state == fileUnknown {
		return fmt.Errorf("检查目标文件是否存在失败（无法确定是否需要备份 %s）: %w", s.path, err)
	}
	if state == fileExists {
		s.existed = true
		backup := s.path + backupSuffix
		if err := os.Rename(s.path, backup); err != nil {
			return fmt.Errorf("备份旧文件失败: %w", err)
		}
		s.backup = backup
		// 备份内容的摘要：恢复前用它确认「这份备份确实是当时那份旧文件」，
		// 而不是一份写了一半、或从别处串过来的东西。
		// 算不出来不影响本次替换，只是让恢复少一层校验（留空即退回旧判据）。
		if sum, err := fileSum(backup); err != nil {
			log.Printf("[lt-config] 计算备份摘要失败（%s），恢复时将退回报份存在性判断: %v", backup, err)
		} else {
			s.bakSum = sum
		}
		syncDirBestEffort(filepath.Dir(s.path))
	}
	if err := os.Rename(s.tmp, s.path); err != nil {
		// 替换失败：把旧文件放回原位。恢复也失败时，磁盘上连旧文件都没了，
		// 必须把这个更糟的情况一并报出去，而不是只报「替换失败」。
		if rerr := s.restore(); rerr != nil {
			return fmt.Errorf("替换失败（%v），且恢复旧文件也失败: %w", err, rerr)
		}
		return err
	}
	// 目录项变更也要落盘：文件内容的 fsync 只覆盖「数据」，rename 之后
	// 断电仍可能看不到新名字（见 syncDirBestEffort 的说明）。
	syncDirBestEffort(filepath.Dir(s.path))
	return nil
}

// restore 回滚：把备份的旧文件放回原位。返回错误表示恢复失败——这时磁盘上
// 可能既没有新文件也没有旧文件（或仍留着新文件），调用方必须如实上报，
// 而不是把它当成「已经回滚好了」。
func (s *stagedFile) restore() error {
	if s.backup != "" {
		// Windows 不允许 Rename 到已存在的目标。先删除新文件，再把备份
		// 放回原位；删除失败时保留现场并返回错误，不能假装已经回滚。
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(s.backup, s.path); err != nil {
			return err
		}
		s.backup = ""
		syncDirBestEffort(filepath.Dir(s.path))
		return nil
	}
	if !s.existed {
		// 目标文件原本不存在：回滚 = 删掉刚创建的新文件，回到「不存在」，
		// 否则磁盘上会留下一个新文件，而其余文件回滚回了旧版本——同样是
		// 新旧混合。文件已不在（并发删除）不视为失败。
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// cleanupBackup 删除备份文件。全部替换成功后在 writeBatch.commit 里调用。
func (s *stagedFile) cleanupBackup() {
	if s.backup != "" {
		_ = os.Remove(s.backup)
		s.backup = ""
	}
}

// discard 放弃候选内容，删掉临时文件。成功 commit 之后调用它也无害。
func (s *stagedFile) discard() {
	_ = os.Remove(s.tmp)
}

// writeFileAtomic 先写同目录临时文件再 rename。
//
// 直接截断原文件的话，写到一半失败（磁盘满、被 kill）就会留下半份配置，
// 而 Caddy 与 frps 都会拒绝加载——一次失败变成一次停机。
func writeFileAtomic(path, content string, mode os.FileMode) error {
	st, err := stageFile(filepath.Base(path), path, content, mode)
	if err != nil {
		return err
	}
	if err := st.commit(); err != nil {
		st.discard()
		return err
	}
	// commit 会给旧文件留一份备份用于失败回滚；单文件写入已经成功，
	// 备份必须当场清掉，否则每写一次就在部署目录多留一个文件
	// （里面是旧凭据），直到下次启动清理才消失。
	st.cleanupBackup()
	return nil
}

// contentSum 返回内容的 sha256 十六进制表示。
//
// 用摘要而不是「内容是不是同一个字符串」：崩溃恢复要判断「磁盘上的文件是不是
// 这一批想写的那份」，而那时原文已经不在内存里了。摘要也存在批次记录里，
// 文件有多少内容都不影响记录的体积。
func contentSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// fileSum 返回文件内容的 sha256 十六进制表示。
//
// 用流式读取而不是 os.ReadFile：这里的文件可能很大（宿主机上的活动配置一般
// 不大，但没理由为它设一个隐含上限），而且摘要只需要一遍扫描。
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
