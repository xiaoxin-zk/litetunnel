package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
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
	// 这个解析器只认识「services: → 两空格缩进 → image:」。遇到 YAML 的
	// 组合能力（锚点、include、merge key、flow 映射）时它不会报错，只会
	// **读不到**，然后返回「找不到 image」——上层再退回默认镜像，校验就又
	// 变成给一个没人用的镜像背书。
	//
	// 与其猜，不如明确指出「看不懂，请让 docker compose 自己解析」。这条
	// 路径只在 docker CLI 不可用时才会走到（composeServiceImageViaDocker
	// 优先），所以提示是可操作的：装上 docker 即可。
	if reason := composeUnsupportedReason(raw); reason != "" {
		return "", fmt.Errorf("compose 文件 %s %s，内置解析器无法可靠读取镜像名："+
			"请安装 docker CLI（将改用 docker compose config 解析）", path, reason)
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

// composeUnsupportedReason 报告手写解析器读不懂的结构（空串表示能处理）。
//
// 判据只认「行首」形态，避免把镜像名或值里的 & 误判成锚点。
func composeUnsupportedReason(raw []byte) string {
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "include:"):
			return fmt.Sprintf("第 %d 行使用了 include", i+1)
		case strings.HasPrefix(trimmed, "extends:"):
			return fmt.Sprintf("第 %d 行使用了 extends", i+1)
		case strings.HasPrefix(trimmed, "<<:") || strings.HasPrefix(trimmed, "- <<:"):
			return fmt.Sprintf("第 %d 行使用了 merge key", i+1)
		case strings.HasSuffix(trimmed, ": &") || strings.Contains(trimmed, ": &"):
			return fmt.Sprintf("第 %d 行使用了 YAML 锚点", i+1)
		case strings.HasPrefix(trimmed, "services: {"):
			return fmt.Sprintf("第 %d 行使用了 flow 风格映射", i+1)
		}
	}
	return ""
}

// composeServiceImageViaDocker 让 Compose 自己解析出某个服务的镜像。
//
// # 为什么在能手写解析的情况下还要调 docker
//
// composeServiceImage 只认「services 下两空格缩进、image: 前缀」这一种写法。
// 本仓库的 compose 文件确实是这么写的，但格式敏感性本身就是缺陷：换成
// YAML 锚点、include、或调整缩进，解析器会读不到而**退回默认值**——
// 于是校验又变成「为一个没人用的镜像背书」，正是这条校验要防的事。
//
// `docker compose config --format json` 是 Compose 自己的解析结果：--env-file、
// 变量插值、extends、anchors 全由它处理。我们只读 JSON 里的 services.<name>.image，
// 不需要引入 YAML 依赖，也不需要跟着 compose 的语义演进。
//
// 返回 ok=false 时调用方退回手写解析：lt-config 也可能部署在没有 docker CLI
// 的宿主机上（此时它只做渲染，不做容器重建），或 compose 版本不支持
// --format json。这不是错误路径，只是「用不了这个更可靠的来源」。
func composeServiceImageViaDocker(composeFile, envFile, service string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	args := []string{"compose", "-f", composeFile}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, "config", "--format", "json")

	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return "", false
	}
	var doc struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return "", false
	}
	svc, ok := doc.Services[service]
	if !ok || strings.TrimSpace(svc.Image) == "" {
		return "", false
	}
	// Compose 已经完成插值，返回的就是容器实际会用的镜像名。
	return strings.TrimSpace(svc.Image), true
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
