package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func composeServiceImage(path, service string) (string, error) {
	raw, err := readConfigInput(path)
	if err != nil {
		return "", err
	}
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
		if lead == 0 {
			inServices = false
			inTarget = false
			continue
		}
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
	return strings.TrimSpace(svc.Image), true
}

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
			return "", false
		}
		switch img[i+1] {
		case '$':
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

func composeExpandBraced(expr string, lookup func(string) string) (string, bool) {
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
		return "", false
	}
	if val == "" {
		return "", false
	}
	return val, true
}

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
