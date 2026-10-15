package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// ensureFrpc 确保内置的 frpc 可执行文件就位，返回它的路径。
//
// # 为什么要把 frpc 内嵌进主程序
//
// 以前发布包里是「LiteTunnel.exe + frpc.exe」两个文件。这对用户是负担：
//
//   - 只解压主程序 → 界面报「未找到 frpc」
//   - 把 frpc.exe 挪到别处 → 同样报错
//   - 杀软误删其中一个 → 现象和上面一样，但更难想到原因
//
// 内嵌之后用户只需要一个 exe，双击就能用。
//
// 返回空字符串表示本次构建未内嵌 frpc（本地开发构建），
// 此时由 frpc.New("") 回退到「在程序目录与 PATH 中查找」，
// 方便开发时直接替换 frpc 调试。
func ensureFrpc() (string, error) {
	if len(embeddedFrpc) == 0 {
		return "", nil
	}

	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, "frpc.exe")

	// 内容一致就直接复用。省掉每次启动重写十几 MB，
	// 也避免在 frpc 正被运行时覆盖自身（Windows 上会失败）。
	if existing, err := os.ReadFile(target); err == nil && bytes.Equal(existing, embeddedFrpc) {
		return target, nil
	}

	// 0600：只给当前用户读写。
	//
	// 这里防的不是提权（用户本来就拥有这台机器），
	// 而是避免同一台机器上的其他账户把它替换成别的程序。
	if err := os.WriteFile(target, embeddedFrpc, 0o600); err != nil {
		// 写不进去不致命：调用方会回退到「同目录查找」，
		// 至少还有一条路能走通。
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	return target, nil
}
