package main

import (
	"fmt"
	"strings"
)

// composeServiceImage 从 compose 文件里读出某个服务的 image。
//
// 为什么需要它：frps 配置的「校验镜像」与 compose 实际启动的镜像必须是同一个。
// 校验用的镜像带不带 verify 子命令、版本是否支持配置里的字段，决定了这次校验
// 到底有没有意义。以前校验镜像来自 LT_CFG_FRPS_IMAGE 的默认值，而 compose 里
// 是一份写死的镜像——管理员改了其中一个，校验就会为一个根本不会上线的镜像背书。
//
// 只做最小解析：找到顶层 services 下的目标服务块，取它的 image 行。compose
// 文件由本仓库维护，格式稳定；遇到读不懂的结构时返回错误，由调用方决定是
// 阻断还是退回默认值——**不能**猜一个镜像去校验。
//
// 读取走 readConfigInput：compose 文件同样是可置换的输入，需要统一的大小上限
// 与文件类型策略（见 safeio.go）。
func composeServiceImage(path, service string) (string, error) {
	raw, err := readConfigInput(path)
	if err != nil {
		return "", err
	}
	inServices := false
	inTarget := false
	indent := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		lead := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		text := strings.TrimSpace(trimmed)

		if text == "services:" {
			inServices = true
			continue
		}
		if !inServices {
			continue
		}
		// 顶层出现另一个键（缩进 0，且不是 services）时，services 段结束。
		if lead == 0 {
			inServices = false
			inTarget = false
			continue
		}
		// 服务名固定缩进 2 层：`  frps:`。
		if lead == 2 && strings.HasSuffix(text, ":") {
			name := strings.TrimSuffix(text, ":")
			inTarget = strings.Trim(name, "\"'") == service
			indent = lead
			continue
		}
		if !inTarget || lead <= indent {
			continue
		}
		if strings.HasPrefix(text, "image:") {
			img := strings.TrimSpace(strings.TrimPrefix(text, "image:"))
			img = strings.Trim(img, "\"'")
			if img == "" {
				return "", fmt.Errorf("服务 %s 的 image 为空", service)
			}
			return img, nil
		}
	}
	return "", fmt.Errorf("compose 文件 %s 中找不到服务 %s 的 image", path, service)
}

// resolveComposeImage 按 Compose 的插值规则展开镜像名里的变量。
//
// 支持的形式（与 compose 的 interpolation 一致）：
//
//	$VAR  ${VAR}  ${VAR:-default}  ${VAR-default}
//	${VAR:+alt}  ${VAR+alt}  ${VAR:?err}  ${VAR?err}  $$（字面量 $）
//
// 返回 ok=false 表示「无法得出一个确定的镜像名」：调用方据此跳过镜像一致性
// 比较，而不是拿一段带 ${} 的原文去比。这里刻意返回三态而不是「猜一个」，
// 因为一个错误的镜像名会让校验为一个不存在/不匹配的镜像背书。
//
// 之前的实现只处理 `}` 结尾的 ${...}，函数注释却写着支持 `$VAR`——文档与
// 实现不一致本身就是缺陷：读代码的人会以为裸写法已经处理过。
func resolveComposeImage(img string, lookup func(string) string) (string, bool) {
	if !strings.Contains(img, "$") {
		return img, true
	}
	var b strings.Builder
	b.Grow(len(img))
	for i := 0; i < len(img); {
		c := img[i]
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(img) {
			// 结尾一个孤立的 $：Compose 会原样保留，但镜像名里出现它没有意义。
			return "", false
		}
		switch img[i+1] {
		case '$':
			// Compose 的转义：$$ 表示一个字面量 $。
			b.WriteByte('$')
			i += 2
			continue
		case '{':
			end := strings.IndexByte(img[i+2:], '}')
			if end < 0 {
				return "", false
			}
			end += i + 2
			val, ok := composeExpandBraced(img[i+2:end], lookup)
			if !ok {
				return "", false
			}
			b.WriteString(val)
			i = end + 1
			continue
		}
		// 裸 $NAME。
		j := i + 1
		for j < len(img) && isComposeVarChar(img[j], j == i+1) {
			j++
		}
		if j == i+1 {
			return "", false
		}
		val := lookup(img[i+1 : j])
		if val == "" {
			return "", false
		}
		b.WriteString(val)
		i = j
	}
	out := b.String()
	if out == "" {
		return "", false
	}
	return out, true
}

// composeExpandBraced 展开 `${...}` 的内容（不含 ${ 与 }）。
func composeExpandBraced(expr string, lookup func(string) string) (string, bool) {
	// 找第一个操作符：:? / ? / :- / - / :+ / +。变量名本身只含
	// [A-Za-z0-9_]，因此第一个非变量名字符就是操作符的起点。
	opIdx := len(expr)
	for i := 0; i < len(expr); i++ {
		if !isComposeVarChar(expr[i], i == 0) {
			opIdx = i
			break
		}
	}
	name := expr[:opIdx]
	if name == "" {
		return "", false
	}
	val := lookup(name)
	if opIdx == len(expr) {
		// 纯 ${VAR}：取不到就说明无法确定，交给调用方阻断。
		if val == "" {
			return "", false
		}
		return val, true
	}
	op := expr[opIdx:]
	switch {
	case strings.HasPrefix(op, ":-"):
		if val == "" {
			val = op[2:]
		}
	case strings.HasPrefix(op, "-"):
		// ${VAR-default}：只在**未设置**时用默认值。这里没有「已设置但为空」
		// 与「未设置」的区别（lookup 只返回值），统一按空处理，两侧一致。
		if val == "" {
			val = op[1:]
		}
	case strings.HasPrefix(op, ":+"):
		if val == "" {
			val = ""
		} else {
			val = op[2:]
		}
	case strings.HasPrefix(op, "+"):
		if val == "" {
			val = ""
		} else {
			val = op[1:]
		}
	case strings.HasPrefix(op, ":?"), strings.HasPrefix(op, "?"):
		if val == "" {
			return "", false
		}
	default:
		// 认不出的操作符：宁可阻断，也不要猜。
		return "", false
	}
	if val == "" {
		return "", false
	}
	return val, true
}

// isComposeVarChar 判断字符能否出现在变量名里（首字符不允许数字）。
func isComposeVarChar(c byte, first bool) bool {
	if c == '_' {
		return true
	}
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if !first && c >= '0' && c <= '9' {
		return true
	}
	return false
}
