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

// ClientPackage 是一个可供分发的客户端安装包。
type ClientPackage struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Updated string `json:"updated_at"`
}

const (
	// MaxClientPackageSize 是单个安装包的大小上限。
	//
	// 取 100 MB：当前客户端包约 30 MB，留出余量。这个限制不能省——
	// 没有它，一次请求就能把服务器磁盘写满，而上传接口是管理端的，
	// 一旦管理员凭据泄露，磁盘会被直接打满。
	MaxClientPackageSize = 100 << 20

	// clientPackageMaxNameLen 限制文件名长度，避免超长名字在各文件系统上的差异。
	clientPackageMaxNameLen = 128
)

// allowedClientExts 是允许上传的扩展名白名单。
//
// 用白名单而不是黑名单：黑名单永远列不全（.php、.jsp、.sh……），
// 而这里只可能分发安装包，白名单足够表达意图。
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

// SanitizeClientFileName 校验并归一化上传的文件名。
//
// # 为什么必须做这一步
//
// 上传的文件名完全来自客户端，是不可信输入。不处理的话，
// 一个叫 "../../etc/cron.d/evil" 的文件会被写到系统目录——
// 这是最经典的路径穿越，且后果是任意文件写入。
//
// 处理方式：
//  1. 取 filepath.Base（剥掉所有目录部分）
//  2. 再显式拒绝 "." 与 ".."（Base 会把它们原样返回）
//  3. 拒绝任何残留的路径分隔符（含 Windows 风格的反斜杠）
//  4. 拒绝隐藏文件（以点开头）
//  5. 扩展名必须在白名单内
func SanitizeClientFileName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w: 文件名为空", ErrInvalidParam)
	}

	// Windows 客户端上传时可能带反斜杠路径，先统一成正斜杠再取 Base。
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

// SaveClientPackage 保存上传的安装包，返回写入的字节数。
//
// 全程流式写入临时文件，校验通过后再原子改名：
//   - 不把整个包读进内存（100 MB 上限下那样做会明显抬高峰值内存）
//   - 失败时目录里不会留下半截文件——它会被列进「可下载」列表，
//     用户下到一个坏包却不知道为什么
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
	// 成功改名后 tmpName 已不存在，Remove 是空操作；
	// 失败路径上它负责清理残骸。
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	// 多读 1 字节用于判断是否超限：直接 LimitReader 到上限的话，
	// 恰好超限一点点的请求会被静默截断成一个坏包。
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

	// 校验文件头。只靠扩展名太容易绕过（把任意文件改名成 .zip），
	// 而管理员上传的文件会被分发给所有用户下载。
	if err := verifyPackageMagic(tmpName, name); err != nil {
		return 0, err
	}

	// 0644：能被 Web 服务读取，但不给执行位——分发目录里只有静态文件。
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return 0, fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return 0, fmt.Errorf("保存文件失败: %w", err)
	}
	return n, nil
}

// verifyPackageMagic 校验文件头与扩展名是否相符。
//
// 只对「格式确定且检查成本极低」的类型做校验：
// zip / exe / gzip / deb / rpm 都有固定魔数，而 dmg、apk 的格式较杂，
// 强行校验反而会误拒正常文件。对它们只做扩展名检查。
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
		// ZIP 的本地文件头是 PK\x03\x04，空归档是 PK\x05\x06。
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
	// .tar / .dmg / .apk 没有可靠的短魔数，只做扩展名检查。
	// 它们的格式本身也很杂（.tar 无魔数、.dmg 有多种变体），
	// 强行校验只会误拒正常文件。
	return nil
}

// ListClientPackages 列出已分发的安装包。
func (s *Services) ListClientPackages() ([]ClientPackage, error) {
	entries, err := os.ReadDir(s.Cfg.ClientDistDir)
	if err != nil {
		if os.IsNotExist(err) {
			// 目录还没建（从未上传过）不是错误，返回空列表。
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
		// 跳过上传中断留下的临时文件。
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

// DeleteClientPackage 删除一个安装包。
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
