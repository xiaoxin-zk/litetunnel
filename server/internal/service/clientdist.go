package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ClientPackage struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Updated string `json:"updated_at"`
}

const (
	MaxClientPackageSize = 100 << 20

	clientPackageMaxNameLen = 128
)

var allowedClientExts = map[string]bool{
	".zip": true,
	".exe": true,
	".dmg": true,
	".deb": true,
	".rpm": true,
	".gz":  true,
	".tar": true,
	".apk": true,
}

func SanitizeClientFileName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w: 文件名为空", ErrInvalidParam)
	}

	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)

	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("%w: 文件名非法", ErrInvalidParam)
	}
	if strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("%w: 文件名不得包含路径分隔符", ErrInvalidParam)
	}
	if strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("%w: 文件名不得以点开头", ErrInvalidParam)
	}
	if len(name) > clientPackageMaxNameLen {
		return "", fmt.Errorf("%w: 文件名过长（上限 %d 字符）", ErrInvalidParam, clientPackageMaxNameLen)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: 文件名含非法字符", ErrInvalidParam)
	}

	ext := strings.ToLower(filepath.Ext(name))
	if !allowedClientExts[ext] {
		return "", fmt.Errorf("%w: 只允许上传安装包（%s）",
			ErrInvalidParam, strings.Join(sortedExts(), "、"))
	}
	return name, nil
}

func sortedExts() []string {
	out := make([]string, 0, len(allowedClientExts))
	for e := range allowedClientExts {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func (s *Services) SaveClientPackage(name string, r io.Reader) (int64, error) {
	dir := s.Cfg.ClientDistDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("创建分发目录失败: %w", err)
	}
	target := filepath.Join(dir, name)

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	n, err := io.Copy(tmp, io.LimitReader(r, MaxClientPackageSize+1))
	if err != nil {
		return 0, fmt.Errorf("写入文件失败: %w", err)
	}
	if n > MaxClientPackageSize {
		return 0, fmt.Errorf("%w: 单个安装包不得超过 %d MB", ErrInvalidParam, MaxClientPackageSize>>20)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: 上传内容为空", ErrInvalidParam)
	}
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("落盘失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("关闭文件失败: %w", err)
	}

	if err := verifyPackageMagic(tmpName, name); err != nil {
		return 0, err
	}

	if err := os.Chmod(tmpName, 0o644); err != nil {
		return 0, fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return 0, fmt.Errorf("保存文件失败: %w", err)
	}
	return n, nil
}

func verifyPackageMagic(path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var head [8]byte
	read, _ := io.ReadFull(f, head[:])
	if read < 2 {
		return fmt.Errorf("%w: 文件内容过短，不是有效的安装包", ErrInvalidParam)
	}

	ext := strings.ToLower(filepath.Ext(name))
	bad := func(want string) error {
		return fmt.Errorf("%w: 文件内容与扩展名 %s 不符（应以 %s 开头）", ErrInvalidParam, ext, want)
	}

	switch ext {
	case ".zip":
		if !(head[0] == 'P' && head[1] == 'K') {
			return bad("PK")
		}
	case ".exe":
		if !(head[0] == 'M' && head[1] == 'Z') {
			return bad("MZ")
		}
	case ".gz":
		if !(head[0] == 0x1f && head[1] == 0x8b) {
			return bad("1F 8B")
		}
	case ".deb":
		if read < 7 || string(head[:7]) != "!<arch>" {
			return bad("!<arch>")
		}
	case ".rpm":
		if !(head[0] == 0xed && head[1] == 0xab && head[2] == 0xee && head[3] == 0xdb) {
			return bad("ED AB EE DB")
		}
	}
	return nil
}

func (s *Services) ListClientPackages() ([]ClientPackage, error) {
	entries, err := os.ReadDir(s.Cfg.ClientDistDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []ClientPackage{}, nil
		}
		return nil, err
	}

	out := make([]ClientPackage, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".upload-") || strings.HasPrefix(name, ".") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		out = append(out, ClientPackage{
			Name:    name,
			Size:    info.Size(),
			Updated: info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Services) DeleteClientPackage(name string) error {
	clean, err := SanitizeClientFileName(name)
	if err != nil {
		return err
	}
	full := filepath.Join(s.Cfg.ClientDistDir, clean)
	if err := os.Remove(full); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}
