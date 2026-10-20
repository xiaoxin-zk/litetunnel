package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// 内嵌 frpc 解压后的合理上限：官方包约 16MB，留足余量同时挡住解压炸弹。
const frpcMaxSize = 64 << 20

func ensureFrpc() (string, error) {
	if len(embeddedFrpcGz) == 0 {
		return "", nil
	}
	want := strings.ToLower(strings.TrimSpace(embeddedFrpcSum))

	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, "frpc.exe")

	// 磁盘上已是构建时那一份就直接用：比较的是解压后的内容哈希，
	// 所以从旧版（内嵌未压缩）客户端升级上来也不会重复写盘。
	if want != "" {
		if sum, err := fileSHA256(target); err == nil && sum == want {
			return target, nil
		}
	}

	raw, err := gunzipFrpc(embeddedFrpcGz)
	if err != nil {
		return "", fmt.Errorf("解压内置 frpc 失败: %w", err)
	}
	if want != "" {
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			return "", fmt.Errorf("内置 frpc 校验失败：期望 %s，实际 %s（安装包可能损坏）", want, got)
		}
	}

	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	if info, err := os.Stat(tmp); err != nil || info.Size() != int64(len(raw)) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败：临时文件长度不一致")
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	return target, nil
}

func gunzipFrpc(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, frpcMaxSize))
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("解压结果为空")
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, frpcMaxSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
