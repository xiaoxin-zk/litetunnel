package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 产物文件的权限。集中在这里定义，避免「某处 0644、某处 0600」这种
// 看代码看不出来、只有 ls -l 才能发现的分叉。
const (
	// modeSecret 用于含凭据的文件：.env 与 frps.toml。
	//
	// .env 里有 DNS API 凭据、JWT 密钥与数据库口令；frps.toml 里有 frps 的
	// 全局 token 与管理 API 密码。0644 意味着同机器上的**任何**普通账号都能
	// 读走它们——足以伪装成客户端接入网关，或者直接调用 frps 管理接口。
	//
	// 0600 不会挡住容器：lt-config 以 root 运行（deploy/systemd/lt-config.service
	// 的 User=root），文件属主就是 root，而以 root 运行的 frps 容器读属主为
	// root、属主位可读的文件，不需要任何额外能力位。
	modeSecret os.FileMode = 0o600
	// modeConfig 用于不含凭据的产物：Caddyfile 里只有域名与 {env.*} 引用，
	// 凭据在容器环境变量里。
	modeConfig os.FileMode = 0o644
)

// envFile 是部署目录下的 .env，按行保存以便「只改动需要改的那几行」。
//
// 为什么不整体重写：.env 是运维手工维护的文件，里面全是注释与分组。
// 重写一遍等于把注释全部抹掉——那样下次出问题时，管理员手上就没有
// 任何线索了。所以这里只替换目标键的值。
type envFile struct {
	path  string
	lines []string
}

// readEnvFile 读取 .env，同时返回解析后的键值表（后者用于渲染）。
//
// 解析规则与 deploy/scripts/render.* 保持一致：忽略空行与 # 注释，
// 只认第一个 '='，键值两端去空白。
//
// 值的解码与 set 的编码互为逆运算（见 encodeEnvValue）：这套文件同时会被
// docker compose --env-file 解析，所以这里必须按 Compose 的 dotenv 语义
// 还原——双引号包裹的值先处理转义（\\ \" 等），单引号包裹的值按字面保留，
// 两种引号之外再统一把 Compose 的转义插值 $$ 还原成 $。老文件里没转义的
// 裸值不含这些序列，解码后原样不变。
func readEnvFile(path string) (*envFile, map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	// Split 会在结尾换行处多出一个空元素，保留它会写出一个多余的空行。
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}

	vars := make(map[string]string, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 1 {
			continue
		}
		// 同名键重复出现时以后者为准，与渲染脚本的解析顺序一致。
		vars[strings.TrimSpace(trimmed[:idx])] = decodeEnvValue(strings.TrimSpace(trimmed[idx+1:]))
	}
	return &envFile{path: path, lines: lines}, vars, nil
}

// decodeEnvValue 按 Compose 的 dotenv 语义还原一个值。
//
// 与 encodeEnvValue 互逆：读回来的值必须等于当初写进去的值，
// 否则「渲染用的凭据」与「容器里实际拿到的凭据」会是两个不同的字符串。
func decodeEnvValue(raw string) string {
	if raw == "" {
		return ""
	}
	// 双引号：转义序列有效（\\、\"、\n、\r、\t），随后再展开插值转义。
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return unescapeDollar(expandEnvEscapes(raw[1 : len(raw)-1]))
	}
	// 单引号：按字面保留（Compose 对单引号值不做转义与插值）。
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1]
	}
	// 裸值：只有插值转义。
	return unescapeDollar(raw)
}

// expandEnvEscapes 处理双引号内的反斜杠转义序列。
func expandEnvEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '\\':
			b.WriteByte('\\')
			i++
		case '"':
			b.WriteByte('"')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		default:
			// 未知转义按字面保留，与 Compose 的容忍行为一致。
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unescapeDollar 把 Compose 的插值转义 $$ 还原成 $。
//
// 按字面替换即可：值里连着三个以上的 $ 在合法凭据里不会出现，
// 也不值得为它维护一套扫描状态机。
func unescapeDollar(s string) string {
	return strings.ReplaceAll(s, "$$", "$")
}

// encodeEnvValue 把值序列化成 Compose 兼容的 .env 行值。
//
// 这份文件会被两个读者解析：
//
//   - docker compose --env-file：值先按 dotenv 语法解析，再做插值，
//     $NAME 与 ${NAME} 都会被当作变量引用展开——DNS 凭据里一个裸的 $
//     会让运行时拿到的值被插值改写，Caddy 拿着错的凭据签不出证书。
//   - 本服务自己的 readEnvFile（编码解码必须互逆，见上）。
//
// 规则：
//   - $ 一律写成 $$（Compose 的转义插值，两种引号下语义一致）；
//   - 含空白、#、引号等会破坏「一行一个值」结构的字符时，用双引号包裹，
//     并转义 \ 与 "（Compose 对双引号值处理这些转义序列）；
//   - 其余字符原样。
//
// 控制字符（换行等）不在这里处理：调用方 set 已经拒绝，那才是安全边界。
func encodeEnvValue(v string) string {
	if v == "" {
		return ""
	}
	quote := strings.ContainsAny(v, " \t#\"'`")
	var b strings.Builder
	b.Grow(len(v) + 2)
	if quote {
		b.WriteByte('"')
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '$':
			b.WriteString("$$")
		case quote && c == '\\':
			b.WriteString(`\\`)
		case quote && c == '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
	if quote {
		b.WriteByte('"')
	}
	return b.String()
}

// set 更新一个键，返回是否真的发生了变化。
//
// 同名键全部更新：解析时是「后者胜」，只改最后一个会让文件里留下一个
// 与生效值不一致的旧行，将来谁读到它都会得出错误结论。
func (e *envFile) set(key, value string) (bool, error) {
	// 值里出现换行，就等于往 .env 里追加额外的一行配置——包括白名单之外的键
	// （LT_CADDY_IMAGE 这类），而 Compose 的插值接受任何来自 .env 的键。
	//
	// 调用方 renderAndApply 已经校验过一次；这里是真正落笔的那一处，再挡一次：
	// 将来新增调用方时，漏掉校验的代价是整个权限边界。
	if tlscfg.HasControlChars(key) || tlscfg.HasControlChars(value) {
		return false, fmt.Errorf("拒绝写入 %s：键或值含有换行或其他控制字符", key)
	}

	// 值必须按 Compose 的 dotenv 语义编码后落盘（见 encodeEnvValue）：
	// 裸写的话，凭据里的 $ 会被 Compose 插值改写，容器拿到的是另一个字符串。
	encoded := encodeEnvValue(value)

	changed := false
	found := false
	for i, line := range e.lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 1 || strings.TrimSpace(trimmed[:idx]) != key {
			continue
		}
		found = true
		next := key + "=" + encoded
		if e.lines[i] != next {
			e.lines[i] = next
			changed = true
		}
	}
	if !found {
		e.lines = append(e.lines, key+"="+encoded)
		return true, nil
	}
	return changed, nil
}

// content 返回写回磁盘的完整内容。
func (e *envFile) content() string {
	return strings.Join(e.lines, "\n") + "\n"
}

// write 原子写入 .env。
//
// 权限**无条件**为 0600：这个文件里有 DNS API 凭据、JWT 密钥与数据库口令。
// 早期版本只在「本次请求带了凭据字段」时才收紧权限，那等于让文件权限取决于
// 调用方这一次带了哪些字段——一个省略字段的合法请求就能把它放回 0644。
func (e *envFile) write() error {
	return writeFileAtomic(e.path, e.content(), modeSecret)
}

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
	if _, err := os.Stat(s.path); err == nil {
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

// syncDirBestEffort 尽力把目录项变更刷到磁盘。
//
// 只对文件做 fsync 是不够的：rename / unlink 这些**目录项**变更由目录本身
// 记录，不同步父目录的话，突然断电后可能出现「.env 已经是新内容、批次记录
// 却不见了」——批次恢复失去唯一依据，磁盘停在半套配置上。
//
// 实现是「尽力而为」：Windows 无法以可 flush 的方式打开目录（返回
// ERROR_INVALID_HANDLE 之类），NTFS 的目录项更新由文件系统日志保证，
// 这里静默跳过。也就是说 Windows 上的恢复保证覆盖进程被强杀与正常掉电，
// 不承诺磁盘写缓存被整体丢弃的极端情形。
func syncDirBestEffort(dir string) {
	if dir == "" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// restore 回滚：把备份的旧文件放回原位。返回错误表示恢复失败——这时磁盘上
// 可能既没有新文件也没有旧文件（或仍留着新文件），调用方必须如实上报，
// 而不是把它当成「已经回滚好了」。
func (s *stagedFile) restore() error {
	if s.backup != "" {
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

// ensureMode 把已存在文件的权限纠正到期望值，返回是否真的改动过。
//
// 内容没变时不会重写文件，但权限可能是早期版本留下的 0644（或被人手工放宽
// 过）：只比较内容就跳过的话，那份宽松权限会一直留在磁盘上。
func ensureMode(path string, mode os.FileMode) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	want := mode.Perm()
	if fi.Mode().Perm() == want {
		return false, nil
	}
	if err := os.Chmod(path, want); err != nil {
		return false, err
	}
	return true, nil
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

// cleanupLeftovers 启动时清理上次异常退出留下的现场。
//
// 三类残留处理方式不同：
//
//   - .lt-config-batch.json 是未完成的批次记录：先按它把整批文件回滚，
//     再走下面的单文件规则（见 recoverBatch）；
//   - .lt-config-tmp-* 是尚未提交的候选内容，谁都没引用，直接删；
//   - *.lt-config-bak 是提交时给旧文件做的备份：目标文件还在（说明新文件已
//     落位、备份是旧的）就删掉；目标文件缺失（崩溃发生在「旧文件改名成备份、
//     新文件还没落位」之间）就把备份恢复回原位——否则活动配置就凭空消失了。
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
			blocked = append(blocked, dir)
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
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
				bak := filepath.Join(dir, name)
				target := strings.TrimSuffix(bak, backupSuffix)
				if _, serr := os.Stat(target); os.IsNotExist(serr) {
					if rerr := os.Rename(bak, target); rerr != nil {
						log.Printf("[lt-config] 恢复遗留备份失败（%s）: %v", name, rerr)
					} else {
						log.Printf("[lt-config] 已恢复遗留备份：%s → %s", name, target)
					}
				} else {
					_ = os.Remove(bak)
				}
			}
		}
	}
	return blocked
}

// sortedKeys 返回有序键名，便于输出稳定的日志与结果。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedChanged 把变化的文件名转成稳定顺序的清单。
func sortedChanged(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// requireVars 从 .env 解析结果里取出必填项。
func requireVars(vars map[string]string, keys []string) error {
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(vars[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("部署目录的 .env 缺少必填项: %s", strings.Join(missing, ", "))
	}
	return nil
}
