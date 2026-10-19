package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateManifestForRecovery(dir string, m batchManifest) error {
	if m.Version != 1 {
		return fmt.Errorf("不支持的 manifest version %d", m.Version)
	}
	if m.Status != "" && m.Status != batchStatusCommitted {
		return fmt.Errorf("不支持的 manifest status %q", m.Status)
	}
	if filepath.Clean(m.Dir) != filepath.Clean(dir) {
		return fmt.Errorf("manifest dir 与所在目录不一致")
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("manifest files 为空")
	}
	seen := make(map[string]struct{}, len(m.Files))
	for _, f := range m.Files {
		if f.Name == "" || f.Path == "" {
			return fmt.Errorf("manifest 文件缺少 name/path")
		}
		path, err := filepath.Abs(filepath.Clean(f.Path))
		if err != nil || filepath.Dir(path) == "." {
			return fmt.Errorf("manifest 路径非法: %q", f.Path)
		}
		if filepath.Dir(path) != filepath.Dir(dir) && !strings.HasPrefix(path, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("manifest 文件越出部署目录: %s", f.Path)
		}
		base := strings.ToLower(filepath.Base(path))
		if base == batchManifestName || strings.HasSuffix(base, backupSuffix) || strings.HasPrefix(base, ".lt-config-tmp-") {
			return fmt.Errorf("manifest 目标使用保留文件名: %s", f.Path)
		}
		if _, ok := seen[path]; ok {
			return fmt.Errorf("manifest 包含重复路径: %s", f.Path)
		}
		seen[path] = struct{}{}
		if f.Tmp != "" {
			tmp, err := filepath.Abs(filepath.Clean(f.Tmp))
			if err != nil || !strings.HasPrefix(tmp, filepath.Clean(dir)+string(os.PathSeparator)) {
				return fmt.Errorf("manifest 临时文件越出部署目录: %s", f.Tmp)
			}
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return fmt.Errorf("manifest 目标是目录: %s", path)
		}
	}
	return nil
}
