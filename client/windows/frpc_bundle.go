package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func ensureFrpc() (string, error) {
	if len(embeddedFrpc) == 0 {
		return "", nil
	}

	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, "frpc.exe")

	if existing, err := os.ReadFile(target); err == nil && bytes.Equal(existing, embeddedFrpc) {
		return target, nil
	}

	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, embeddedFrpc, 0o600); err != nil {
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	if info, err := os.Stat(tmp); err != nil || info.Size() != int64(len(embeddedFrpc)) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败：临时文件长度不一致")
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	return target, nil
}
