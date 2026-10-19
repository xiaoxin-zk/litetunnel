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
	// 以**解析符号链接之后**的部署根为边界。
	//
	// 只比较字面路径不够：部署目录本身可能是一个符号链接（/opt/lt →
	// /data/lt），此时 manifest 里写的是 /opt/lt/...，而真实文件在
	// /data/lt 下；反过来，一个指向目录树之外的父目录链接也能让字面
	// 路径通过检查，实际删除却发生在部署根之外。
	root, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("无法解析部署目录的真实路径（%s）: %w", dir, err)
	}

	withinRoot := func(p string) bool {
		return p == root || strings.HasPrefix(p, root+string(os.PathSeparator))
	}

	// resolveParent 返回目标文件父目录的真实路径。
	resolveParent := func(p string) (string, error) {
		real, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil {
			return "", fmt.Errorf("无法解析 %s 的父目录（可能不存在或是悬空链接）: %w", p, err)
		}
		return real, nil
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
		parent, err := resolveParent(path)
		if err != nil {
			return err
		}
		if !withinRoot(parent) {
			return fmt.Errorf("manifest 文件越出部署目录（真实路径 %s）: %s", parent, f.Path)
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
			if err != nil {
				return fmt.Errorf("manifest 临时文件路径非法: %s", f.Tmp)
			}
			tmpParent, err := resolveParent(tmp)
			if err != nil {
				return err
			}
			if !withinRoot(tmpParent) {
				return fmt.Errorf("manifest 临时文件越出部署目录（真实路径 %s）: %s", tmpParent, f.Tmp)
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
