package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// UpdateInfo 是面板返回的版本信息，客户端只负责展示与下载。
// 客户端是绿色版 zip：运行中的 exe 不能被自己覆盖，所以不做静默替换，
// 而是下载到「下载」目录后帮用户定位文件，由用户退出后解压覆盖。
type UpdateInfo struct {
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	HasUpdate   bool   `json:"has_update"`
	Comparable  bool   `json:"comparable"`
	DownloadURL string `json:"download_url"`
	ChecksumURL string `json:"checksum_url"`
	ReleaseURL  string `json:"release_url"`
	Notes       string `json:"notes"`
	Error       string `json:"error,omitempty"`
	LocalPath   string `json:"local_path,omitempty"`
}

func (a *App) CheckUpdate() UpdateInfo {
	out := UpdateInfo{Current: Version()}
	base := a.serverBase()
	if base == "" {
		out.Error = "尚未接入服务器，无法检查更新"
		return out
	}
	a.mu.RLock()
	key := a.cfg.APIKey
	a.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint := base + "/api/user/client/version?current=" + url.QueryEscape(Version())
	if err := a.getJSON(ctx, endpoint, key, &out); err != nil {
		out.Error = err.Error()
	}
	if out.Current == "" {
		out.Current = Version()
	}
	return out
}

// DownloadClientUpdate 下载新版本 zip 并校验 sha256，随后在资源管理器中定位该文件。
func (a *App) DownloadClientUpdate() (UpdateInfo, error) {
	info := a.CheckUpdate()
	if info.Error != "" {
		return info, errors.New(info.Error)
	}
	if !info.HasUpdate {
		return info, errors.New("当前已是最新版本")
	}
	if info.DownloadURL == "" {
		return info, errors.New("该版本没有提供 Windows 客户端下载")
	}

	dir := downloadDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return info, fmt.Errorf("创建下载目录失败: %w", err)
	}
	name := fmt.Sprintf("LiteTunnel-%s-windows-amd64.zip", strings.TrimPrefix(info.Latest, "v"))
	target := filepath.Join(dir, name)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sum, err := downloadFile(ctx, info.DownloadURL, target)
	if err != nil {
		return info, err
	}

	if info.ChecksumURL != "" {
		want, err := fetchChecksum(ctx, info.ChecksumURL, name)
		if err != nil {
			return info, err
		}
		if want != "" && want != sum {
			_ = os.Remove(target)
			return info, errors.New("下载文件的 SHA-256 与发布页不一致，已删除，请重试或手动下载")
		}
	}

	info.LocalPath = target
	// 尽力打开资源管理器并选中文件；打不开不影响下载结果。
	_ = exec.Command("explorer", "/select,", target).Start()
	return info, nil
}

func downloadDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "Downloads")
	}
	return os.TempDir()
}

func downloadFile(ctx context.Context, src, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "LiteTunnel-Client")

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败: 服务器返回 %d", resp.StatusCode)
	}

	tmp := target + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", fmt.Errorf("写入文件失败: %w", err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(resp.Body, 512<<20))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("下载中断: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("写入文件失败: %w", closeErr)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("保存文件失败: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fetchChecksum(ctx context.Context, src, fileName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("读取校验和失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("读取校验和失败: 服务器返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("读取校验和失败: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && len(fields[0]) == 64 && strings.Contains(line, fileName) {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", nil
}
