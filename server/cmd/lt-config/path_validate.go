package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateManagedPaths 校验配置工具管理的输出路径不会互相覆盖，也不会占用
// 批次恢复使用的保留文件名。路径先绝对化、清理，再比较；若目标已经存在，
// 额外解析软链接，避免两个逻辑路径最终指向同一个文件。
func validateManagedPaths(p paths) error {
	managed := []struct {
		name string
		path string
	}{
		{"Caddyfile", p.caddyOut},
		{"frps.toml", p.frpsOut},
		{".env", p.envFile},
	}
	canonical := make(map[string]string, len(managed))
	for _, item := range managed {
		path := filepath.Clean(item.path)
		if path == "." || path == "" {
			return fmt.Errorf("%s 输出路径为空", item.name)
		}
		base := strings.ToLower(filepath.Base(path))
		if base == batchManifestName || strings.HasSuffix(base, backupSuffix) ||
			strings.HasPrefix(base, ".lt-config-tmp-") {
			return fmt.Errorf("%s 输出路径使用了配置事务保留文件名：%s", item.name, path)
		}
		key := strings.ToLower(path)
		if prev, ok := canonical[key]; ok {
			return fmt.Errorf("%s 与 %s 使用了相同输出路径：%s", item.name, prev, path)
		}
		canonical[key] = item.name

		if real, err := filepath.EvalSymlinks(path); err == nil {
			realKey := strings.ToLower(filepath.Clean(real))
			if prev, ok := canonical[realKey]; ok && prev != item.name {
				return fmt.Errorf("%s 与 %s 通过符号链接指向同一文件：%s", item.name, prev, real)
			}
			canonical[realKey] = item.name
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("无法解析 %s 输出路径 %s：%w", item.name, path, err)
		}
	}
	return nil
}
