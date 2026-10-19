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

func Render(tpl string, vars map[string]string) (string, error) {
	text := strings.ReplaceAll(tpl, "\r\n", "\n")
	lines := strings.Split(text, "\n")

	kept := applyConditionals(lines, vars)
	body := strings.Join(kept, "\n")

	out := substitute(body, vars)

	if leftover := LeftoverPlaceholders(out); len(leftover) > 0 {
		return "", fmt.Errorf("模板中存在未替换的占位符（缺少对应变量）: %s", strings.Join(leftover, ", "))
	}
	return out, nil
}

func applyConditionals(lines []string, vars map[string]string) []string {
	out := make([]string, 0, len(lines))
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
			continue
		}
		if keep[len(keep)-1] {
			out = append(out, line)
		}
	}
	return out
}

func substitute(text string, vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
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

func mask(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", 6) + string(r[len(r)-2:])
}
