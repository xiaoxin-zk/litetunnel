package main

import (
	"fmt"
	"os"
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
func composeServiceImage(path, service string) (string, error) {
	raw, err := os.ReadFile(path)
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

// resolveComposeImage 解析 `${VAR:-default}` / `${VAR}` / `$VAR` 形式。
//
// 只处理环境变量（COMPOSE 的插值来源之一）。无法解析时返回 ok=false：
// 调用方据此跳过「镜像一致性」比较，而不是拿一段带 ${} 的原文去比。
func resolveComposeImage(img string, lookup func(string) string) (string, bool) {
	if !strings.Contains(img, "$") {
		return img, true
	}
	out := img
	for {
		start := strings.Index(out, "${")
		if start < 0 {
			break
		}
		end := strings.Index(out[start:], "}")
		if end < 0 {
			return "", false
		}
		end += start
		expr := out[start+2 : end]
		name, def := expr, ""
		if i := strings.Index(expr, ":-"); i >= 0 {
			name, def = expr[:i], expr[i+2:]
		}
		val := lookup(name)
		if val == "" {
			val = def
		}
		if val == "" {
			return "", false
		}
		out = out[:start] + val + out[end+1:]
	}
	if strings.Contains(out, "$") {
		return "", false
	}
	return out, true
}
