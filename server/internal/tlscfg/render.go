package tlscfg

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	reIf        = regexp.MustCompile(`^\s*#\s*@if\s+([A-Za-z0-9_]+)\s*$`)
	reEndif     = regexp.MustCompile(`^\s*#\s*@endif\s*$`)
	rePlacehold = regexp.MustCompile(`\$\{[A-Za-z0-9_]+\}`)
)

// Render 渲染模板，语义与 deploy/scripts/render.{sh,ps1} **完全一致**。
//
// 两处必须同步，否则「在界面里保存的配置」与「手工跑脚本生成的配置」
// 会产出不同结果，而这种差异只会在某次重启后以「配置莫名回退了」的形式暴露：
//
//  1. `# @if VAR` 与 `# @endif` 之间的片段，在 VAR 为空（或未定义）时整段删除，
//     支持嵌套；
//  2. 其余位置做 ${VAR} 替换，键长优先（避免 LT_USER_PORT 误伤 LT_USER_PORT_X）；
//  3. 替换完成后不允许残留任何 ${...}：少了变量的配置会被 Caddy 直接拒绝加载
//     整份文件，那种失败发生在「重启 Caddy 之后」，排查成本极高，这里提前挡掉。
//
// 输出统一用 LF：产物是给 Linux 上的 Caddy / frps 读的，
// 而模板在 Windows 检出时可能是 CRLF。
func Render(tpl string, vars map[string]string) (string, error) {
	text := strings.ReplaceAll(tpl, "\r\n", "\n")
	lines := strings.Split(text, "\n")

	kept := applyConditionals(lines, vars)
	body := strings.Join(kept, "\n")

	// Split 会为结尾的换行多出一个空元素，正好还原成尾部换行，
	// 因此这里不需要额外补。
	out := substitute(body, vars)

	if leftover := LeftoverPlaceholders(out); len(leftover) > 0 {
		return "", fmt.Errorf("模板中存在未替换的占位符（缺少对应变量）: %s", strings.Join(leftover, ", "))
	}
	return out, nil
}

// applyConditionals 处理 `# @if VAR` / `# @endif`。
//
// 为什么是「整段删除」而不是「替换成空值」：模板里被包住的往往是
// 「变量为空时不成立」的整块配置（例如泛域名站点块）。替换成空值会得到
// 一个地址行是空白的站点块，而 Caddy 会因此拒绝加载整份 Caddyfile——
// 一个可选项没填，代价是整个反代起不来。
func applyConditionals(lines []string, vars map[string]string) []string {
	out := make([]string, 0, len(lines))
	// 每层一个布尔：只有所有外层都保留时，当前层才可能保留。
	keep := []bool{true}

	for _, line := range lines {
		if m := reIf.FindStringSubmatch(line); m != nil {
			parent := keep[len(keep)-1]
			keep = append(keep, parent && strings.TrimSpace(vars[m[1]]) != "")
			continue
		}
		if reEndif.MatchString(line) {
			if len(keep) > 1 {
				keep = keep[:len(keep)-1]
			}
			// 多余的 @endif 直接忽略：与脚本一致，不因此让整次渲染失败。
			continue
		}
		if keep[len(keep)-1] {
			out = append(out, line)
		}
	}
	return out
}

// substitute 做 ${VAR} 替换，键长的先替换。
func substitute(text string, vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	// 长键优先：否则 ${LT_USER_PORT} 会把 ${LT_USER_PORT_X} 打出半个残片。
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		text = strings.ReplaceAll(text, "${"+k+"}", vars[k])
	}
	return text
}

// LeftoverPlaceholders 返回渲染结果里仍然存在的占位符（去重、有序）。
func LeftoverPlaceholders(text string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range rePlacehold.FindAllString(text, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// Redact 把变量集合里的密钥值抹掉，供日志与错误信息使用。
//
// 打印一份「准备渲染的变量」是排查配置问题最有效的手段，
// 但这份内容里有 DNS API 凭据——所以必须经过它。
func Redact(vars map[string]string) map[string]string {
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		if SecretVars[k] && v != "" {
			out[k] = mask(v)
			continue
		}
		out[k] = v
	}
	return out
}

// mask 只保留首尾各 2 个字符，中间用 * 代替；过短的直接全遮。
func mask(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", 6) + string(r[len(r)-2:])
}
