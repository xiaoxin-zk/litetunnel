package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveManagedPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func managedOutputPaths(p paths) (map[string]bool, error) {
	out := make(map[string]bool, 3)
	for _, f := range []string{p.caddyOut, p.frpsOut, p.envFile} {
		if strings.TrimSpace(f) == "" {
			continue
		}
		real, err := resolveManagedPath(f)
		if err != nil {
			return nil, fmt.Errorf("无法解析受管文件 %s 的真实路径: %w", f, err)
		}
		out[real] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有配置任何受管输出文件")
	}
	return out, nil
}

func validateManifestForRecovery(dir string, m batchManifest, managed map[string]bool) error {
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
	if len(m.Files) > maxManifestFiles {
		return fmt.Errorf("manifest 条目数 %d 超过上限 %d", len(m.Files), maxManifestFiles)
	}

	seen := make(map[string]struct{}, len(m.Files))
	for _, f := range m.Files {
		if f.Name == "" || f.Path == "" {
			return fmt.Errorf("manifest 文件缺少 name/path")
		}
		if len(f.Name) > maxManifestFieldLen || len(f.Path) > maxManifestPathLen ||
			len(f.Tmp) > maxManifestPathLen {
			return fmt.Errorf("manifest 字段超长: %q", f.Name)
		}

		path, err := filepath.Abs(filepath.Clean(f.Path))
		if err != nil {
			return fmt.Errorf("manifest 路径非法: %q", f.Path)
		}
		real, err := resolveManagedPath(path)
		if err != nil {
			return fmt.Errorf("无法解析 manifest 目标 %s 的真实路径: %w", path, err)
		}
		if !managed[real] {
			return fmt.Errorf("manifest 目标不是受管输出文件: %s（真实路径 %s）", f.Path, real)
		}

		base := strings.ToLower(filepath.Base(path))
		if base == batchManifestName || strings.HasSuffix(base, backupSuffix) || strings.HasPrefix(base, ".lt-config-tmp-") {
			return fmt.Errorf("manifest 目标使用保留文件名: %s", f.Path)
		}
		if _, ok := seen[real]; ok {
			return fmt.Errorf("manifest 包含重复路径: %s", f.Path)
		}
		seen[real] = struct{}{}

		if f.Tmp != "" {
			tmp, err := filepath.Abs(filepath.Clean(f.Tmp))
			if err != nil {
				return fmt.Errorf("manifest 临时文件路径非法: %s", f.Tmp)
			}
			if filepath.Dir(tmp) != filepath.Dir(path) {
				return fmt.Errorf("manifest 临时文件不在目标目录内: %s", f.Tmp)
			}
			if !strings.HasPrefix(strings.ToLower(filepath.Base(tmp)), ".lt-config-tmp-") {
				return fmt.Errorf("manifest 临时文件不是本服务创建的临时文件: %s", f.Tmp)
			}
		}

		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("manifest 目标不能是符号链接: %s", path)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("manifest 目标不是普通文件: %s", path)
			}
		}
	}
	return nil
}

const (
	maxManifestFiles    = 16
	maxManifestFieldLen = 128
	maxManifestPathLen  = 4096
	maxManifestBytes    = 256 << 10
)
