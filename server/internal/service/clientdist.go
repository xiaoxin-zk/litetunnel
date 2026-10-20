package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	// GitHub Release 的 .sha256 产物只有一行，留足余量即可。
	clientChecksumMaxRead = 4 << 10
	// 服务端代下载安装包的超时：公网到 GitHub 可能较慢，但也不该无限等。
	clientSyncTimeout = 10 * time.Minute
	// 下载地址的有效期。短到即使 URL 进了访问日志也基本没有利用窗口，
	// 又足够浏览器从点击到真正发起下载（含一次重定向/重试）。
	clientDownloadTicketTTL = 3 * time.Minute
)

// clientDownloadKey 从 JWT 密钥派生下载专用子密钥。
// 不复用登录密钥本身：两处用途不同，泄露一处不应连带另一处。
func (s *Services) clientDownloadKey() []byte {
	mac := hmac.New(sha256.New, []byte(s.Cfg.UserJWTSecret))
	mac.Write([]byte("litetunnel/client-download/v1"))
	return mac.Sum(nil)
}

// ClientDownloadTicket 签发短时下载票据。票据绑定用户与文件名：
// 换名字、换用户、改过期时间都会让签名对不上。
func (s *Services) ClientDownloadTicket(userID uint, name string) (string, time.Time) {
	exp := time.Now().Add(clientDownloadTicketTTL)
	payload := strconv.FormatUint(uint64(userID), 10) + "\n" + name + "\n" +
		strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, s.clientDownloadKey())
	mac.Write([]byte(payload))
	return strconv.FormatUint(uint64(userID), 10) + "." +
		strconv.FormatInt(exp.Unix(), 10) + "." + hex.EncodeToString(mac.Sum(nil)), exp
}

// VerifyClientDownloadTicket 校验票据，返回签发票据的用户。
func (s *Services) VerifyClientDownloadTicket(name, ticket string) (uint, bool) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 3 {
		return 0, false
	}
	uid, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || uid == 0 {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	payload := parts[0] + "\n" + name + "\n" + parts[1]
	mac := hmac.New(sha256.New, s.clientDownloadKey())
	mac.Write([]byte(payload))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(want), []byte(parts[2])) != 1 {
		return 0, false
	}
	return uint(uid), true
}

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
	return s.saveClientPackage(name, r, nil)
}

// saveClientPackage 写入临时文件 → 校验 → 原子改名。
// verify 在改名**之前**执行，拿到的是落在磁盘上的临时文件路径：
// 校验失败时旧文件保持原样，不会出现「新包是坏的、旧的已经被覆盖」。
func (s *Services) saveClientPackage(name string, r io.Reader, verify func(tmpPath string) error) (int64, error) {
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
	if verify != nil {
		if err := verify(tmpName); err != nil {
			return 0, err
		}
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

// SyncClientPackageFromRelease 从最新 GitHub Release 下载安装包到分发目录。
//
// 存在的意义是别再让管理员「先下 11MB 再传 11MB」：管理后台往往通过公网
// 访问，浏览器上传受限于家里的上行带宽；而面板服务器到 GitHub 的链路通常
// 更快，一次点击即可完成。Release 附带的 .sha256 会一并下载并校验，
// 校验在临时文件上做，坏包不会覆盖目录里已有的同名文件。
func (s *Services) SyncClientPackageFromRelease(ctx context.Context, assetName string) (string, int64, string, error) {
	status, err := s.CheckUpdate(ctx, true)
	if err != nil {
		return "", 0, "", err
	}
	if strings.TrimSpace(assetName) == "" {
		assetName = clientAssetName
	}
	name, err := SanitizeClientFileName(assetName)
	if err != nil {
		return "", 0, "", err
	}

	var srcURL, sumURL string
	var assetSize int64
	for _, a := range status.Assets {
		switch a.Name {
		case name:
			srcURL, assetSize = a.URL, a.Size
		case name + clientChecksumSuffix:
			sumURL = a.URL
		}
	}
	if srcURL == "" {
		return "", 0, "", fmt.Errorf("%w: 最新版本 %s 里没有 %s", ErrNotFound, status.Latest, name)
	}
	if assetSize > MaxClientPackageSize {
		return "", 0, "", fmt.Errorf("%w: 发布包 %s 超过 %d MB 上限",
			ErrInvalidParam, name, MaxClientPackageSize>>20)
	}

	reqCtx, cancel := context.WithTimeout(ctx, clientSyncTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, srcURL, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "LiteTunnel-Panel")
	if token := strings.TrimSpace(os.Getenv("LT_UPDATE_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: clientSyncTimeout}).Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("下载安装包失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("下载安装包失败: GitHub 返回 HTTP %d", resp.StatusCode)
	}

	var wantSum string
	if sumURL != "" {
		// 校验和拿不到不阻断下载：老 Release 可能没传 .sha256，
		// 但拿到了就必须对得上（见下面的 verify 回调）。
		if sum, serr := fetchReleaseChecksum(reqCtx, sumURL); serr == nil {
			wantSum = sum
		}
	}

	verify := func(tmpPath string) error {
		if wantSum == "" {
			return nil
		}
		sum, herr := fileSHA256(tmpPath)
		if herr != nil {
			return fmt.Errorf("读取临时文件失败: %w", herr)
		}
		if !strings.EqualFold(sum, wantSum) {
			return fmt.Errorf("安装包校验失败：期望 %s，实际 %s（下载内容可能被截断或篡改）", wantSum, sum)
		}
		return nil
	}

	n, err := s.saveClientPackage(name, resp.Body, verify)
	if err != nil {
		return "", 0, "", err
	}
	return name, n, status.Latest, nil
}

// fetchReleaseChecksum 读取 Release 上的 .sha256 文件（形如 `<hash>  <文件名>`）。
func fetchReleaseChecksum(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "LiteTunnel-Panel")
	if token := strings.TrimSpace(os.Getenv("LT_UPDATE_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("校验和下载失败: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, clientChecksumMaxRead))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 1 && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", errors.New("校验和文件格式无法识别")
}

