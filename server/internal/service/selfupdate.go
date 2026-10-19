package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	ErrSelfUpdateUnavailable = errors.New("当前部署方式不支持在线更新：容器内替换二进制会在重启后失效，" +
		"请按弹层里的命令换镜像；二进制部署请设置 LT_SELF_UPDATE=1")
	ErrSelfUpdateUnsupported = errors.New("当前平台没有对应的一键更新产物")
)

const (
	panelBinaryName  = "litetunnel-panel"
	panelBackupName  = "litetunnel-panel.old"
	selfUpdateMaxTar = 200 << 20
)

func runningInContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("LT_CONTAINER")), "1")
}

func selfUpdateEnvEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LT_SELF_UPDATE"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".lt-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// SelfUpdateState 返回「能否在线更新」与部署形态。
// 容器里永远为 false：镜像不可变，改了 /app 里的二进制，重启后一样回到旧镜像。
func (s *Services) SelfUpdateState() (bool, string) {
	if runningInContainer() {
		return false, "docker"
	}
	if !selfUpdateEnvEnabled() {
		return false, "binary"
	}
	exe, err := os.Executable()
	if err != nil {
		return false, "binary"
	}
	if runtime.GOOS != "linux" {
		// 目前只发布 linux 面板产物；Windows 面板请用镜像或手动替换。
		return false, "binary"
	}
	if !dirWritable(filepath.Dir(exe)) {
		return false, "binary"
	}
	return true, "binary"
}

func panelAssetName() string {
	return fmt.Sprintf("%s-linux-%s.tar.gz", panelBinaryName, runtime.GOARCH)
}

// ApplyPanelUpdate 下载并校验新版本，原子替换当前可执行文件。旧文件保留为 .old 便于回滚。
// 替换后需要重启进程才会生效（见 RestartPanel）。
func (s *Services) ApplyPanelUpdate(ctx context.Context) (string, error) {
	ok, _ := s.SelfUpdateState()
	if !ok {
		return "", ErrSelfUpdateUnavailable
	}

	status, err := s.CheckUpdate(ctx, true)
	if err != nil {
		return "", err
	}
	if !status.HasUpdate {
		return "", errors.New("当前已是最新版本")
	}

	assetName := panelAssetName()
	var downloadURL, checksumURL string
	for _, a := range status.Assets {
		switch a.Name {
		case assetName:
			downloadURL = a.URL
		case assetName + clientChecksumSuffix:
			checksumURL = a.URL
		}
	}
	if downloadURL == "" {
		return "", ErrSelfUpdateUnsupported
	}
	if checksumURL == "" {
		return "", errors.New("该版本缺少校验和，拒绝对可执行文件做未校验的替换")
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)

	archive := filepath.Join(dir, ".panel-update.tar.gz")
	if err := downloadToFile(ctx, downloadURL, archive); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(archive) }()

	want, err := fetchChecksumFile(ctx, checksumURL, assetName)
	if err != nil {
		return "", err
	}
	if want == "" {
		return "", errors.New("校验和文件里没有当前产物的记录")
	}
	got, err := fileSHA256(archive)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", errors.New("下载包的 SHA-256 与发布页不一致，已放弃更新")
	}

	newPath := filepath.Join(dir, panelBinaryName+".new")
	if err := extractPanelBinary(archive, newPath); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(newPath) }()

	backup := filepath.Join(dir, panelBackupName)
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		return "", fmt.Errorf("备份当前版本失败（目录不可写？）: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		// 换不回去就等于服务没了，立刻还原备份。
		_ = os.Rename(backup, exe)
		return "", fmt.Errorf("替换可执行文件失败: %w", err)
	}
	log.Printf("[selfupdate] 已替换面板二进制：%s -> %s，等待重启生效", status.Current, status.Latest)
	return status.Latest, nil
}

// RestartPanel 在响应写回之后重新执行自身进程（Linux 下 syscall.Exec，PID 不变）。
func (s *Services) RestartPanel() {
	go func() {
		time.Sleep(400 * time.Millisecond)
		if err := reExecSelf(); err != nil {
			log.Printf("[selfupdate] 重启失败，请手动重启服务: %v", err)
		}
	}()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func downloadToFile(ctx context.Context, src, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "LiteTunnel-Panel")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("下载更新包失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载更新包失败: 服务器返回 %d", resp.StatusCode)
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, io.LimitReader(resp.Body, selfUpdateMaxTar))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func fetchChecksumFile(ctx context.Context, src, fileName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("读取校验和失败: 服务器返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && len(fields[0]) == 64 && strings.Contains(line, fileName) {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", nil
}

// extractPanelBinary 只认压缩包里名为 litetunnel-panel 的那一个文件，其余一律忽略，
// 避免被塞进软链或目录穿越路径。
func extractPanelBinary(archive, target string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != panelBinaryName || hdr.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, selfUpdateMaxTar)); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chmod(target, 0o755)
	}
	return errors.New("更新包里没有找到 litetunnel-panel")
}
