package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// validateManagedPaths 校验配置工具管理的输出路径不会互相覆盖，也不会占用
// 批次恢复使用的保留文件名。路径先绝对化、清理，再比较；若目标已经存在，
// 额外解析软链接，避免两个逻辑路径最终指向同一个文件。
func validateManagedPaths(p paths) error {
	managed := []struct {
		name   string
		path   string
		output bool
	}{
		{"Caddyfile", p.caddyOut, true},
		{"frps.toml", p.frpsOut, true},
		{".env", p.envFile, true},
		{"Caddyfile 模板", p.caddyTpl, false},
		{"frps.toml 模板", p.frpsTpl, false},
		{"Compose 文件", p.composeFile, false},
	}
	canonical := make(map[string]string, len(managed))
	for _, item := range managed {
		path := filepath.Clean(item.path)
		if path == "." || path == "" {
			return fmt.Errorf("%s 输出路径为空", item.name)
		}
		base := strings.ToLower(filepath.Base(path))
		if item.output && (base == batchManifestName || strings.HasSuffix(base, backupSuffix) ||
			strings.HasPrefix(base, ".lt-config-tmp-")) {
			return fmt.Errorf("%s 输出路径使用了配置事务保留文件名：%s", item.name, path)
		}
		key := strings.ToLower(path)
		if prev, ok := canonical[key]; ok {
			return fmt.Errorf("%s 与 %s 指向同一路径：%s", item.name, prev, path)
		}
		canonical[key] = item.name

		// 解析真实路径。目标不存在时也要解析**父目录**：一个指向部署目录
		// 之外的父目录符号链接，会让 CreateTemp/写入跟随到那个目录去，
		// 而字面路径看起来完全正常。
		real, err := resolveManagedPath(path)
		if err != nil {
			return fmt.Errorf("无法解析 %s 输出路径 %s 的真实位置：%w", item.name, path, err)
		}
		realKey := strings.ToLower(real)
		if prev, ok := canonical[realKey]; ok && prev != item.name {
			return fmt.Errorf("%s 与 %s 指向同一文件（真实路径 %s）", item.name, prev, real)
		}
		canonical[realKey] = item.name
	}
	return nil
}
