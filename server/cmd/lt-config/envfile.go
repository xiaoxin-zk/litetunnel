package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
func (e *envFile) set(key, value string) bool {
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
		return true
	}
	return changed
}

// write 原子写入。
//
// secret 为真时把权限收紧到 0600：这个文件里有 DNS API 凭据、
// JWT 密钥与数据库口令，默认的 0644 在同机多用户场景下等于公开。
func (e *envFile) write(secret bool) error {
	mode := os.FileMode(0o600)
	if !secret {
		mode = 0o644
	}
	return writeFileAtomic(e.path, strings.Join(e.lines, "\n")+"\n", mode)
}

// writeFileAtomic 先写同目录临时文件再 rename。
//
// 直接截断原文件的话，写到一半失败（磁盘满、被 kill）就会留下半份配置，
// 而 Caddy 与 frps 都会拒绝加载——一次失败变成一次停机。
func writeFileAtomic(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".lt-config-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		// 成功路径上文件已被 rename，这里的 Remove 会失败，忽略即可。
		_ = os.Remove(tmp)
	}()

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
