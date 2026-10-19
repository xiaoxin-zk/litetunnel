package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveManagedPath 返回一个受管文件的真实绝对路径，用于白名单比较。
//
// 文件可能存在、可能不存在（第一次写入前）。不存在时解析父目录的真实路径
// 再拼上文件名：父目录若是指向部署目录之外的符号链接，拼出来的路径自然也
// 在目录之外，白名单比较就会失败——这正是我们要的结果。
func resolveManagedPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	} else if !os.IsNotExist(err) {
		// 判不出来（ELOOP、权限）时不能猜：交给调用方决定阻断。
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// managedOutputPaths 返回本服务受管的输出文件白名单（真实绝对路径）。
//
// 为什么不按「部署目录前缀」判断：默认布局里 Caddyfile 在 deploy/caddy、
// frps.toml 在 deploy/frps、.env 在 deploy 的父目录，三者根本不在同一棵
// 子树下。按目录前缀放行要么误拒正常布局（恢复永远失败、目录被永久阻断），
// 要么为了放行而把范围放宽到整个仓库甚至父目录——后者等于没有边界。
// 精确白名单同时满足正确性与安全性。
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
	// 损坏的记录可能有成千上万条：逐条 stat 之前先挡掉明显超限的。
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
		// 只允许指向**本服务实际管理的三个输出文件**。manifest 是磁盘上的
		// 普通文件，任何能写部署目录的人都能改它；按路径集合放行，等于
		// 把「恢复可以删/改哪些文件」钉死在配置上。
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
			// 临时文件由 CreateTemp 在目标目录里创建，只允许同目录下的
			// 保留前缀文件；不跟随链接、不跨目录。
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
	// maxManifestFiles 是一批最多涉及的文件数。本服务只写三个文件，
	// 给到 16 已经足够宽裕；再大只可能是损坏或被构造的记录。
	maxManifestFiles = 16
	// maxManifestFieldLen 限制 name 这类短字段。
	maxManifestFieldLen = 128
	// maxManifestPathLen 限制路径字段，避免把整份记录撑成几 MB。
	maxManifestPathLen = 4096
	// maxManifestBytes 是读取 manifest 时允许的最大体积。
	maxManifestBytes = 256 << 10
)
