package main

import (
	"fmt"
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
		vars[strings.TrimSpace(trimmed[:idx])] = strings.TrimSpace(trimmed[idx+1:])
	}
	return &envFile{path: path, lines: lines}, vars, nil
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
		next := key + "=" + value
		if e.lines[i] != next {
			e.lines[i] = next
			changed = true
		}
	}
	if !found {
		e.lines = append(e.lines, key+"="+value)
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
}

// stageFile 把内容写进同目录的临时文件并设好权限，内容尚未生效。
func stageFile(name, path, content string, mode os.FileMode) (*stagedFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".lt-config-tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	st := &stagedFile{name: name, path: path, tmp: tmp}

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

// commit 把候选内容原子替换到目标路径。
func (s *stagedFile) commit() error {
	return os.Rename(s.tmp, s.path)
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
	return nil
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
