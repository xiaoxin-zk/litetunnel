package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

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
