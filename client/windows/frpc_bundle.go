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

	// 先写临时文件、成功后再原子替换，绝不直接覆盖目标。
	//
	// 直接 WriteFile 覆盖的话，写到一半被强杀或被杀软拦截，目标路径上会
	// 留下一个半写的 frpc.exe；而下面判断「存在」只靠内容比对，残缺文件
	// 既不能执行、又可能因为长度不同而反复触发重写。写临时文件再 Rename，
	// 目标在任何时刻要么是上一份完整可用的、要么是这一份完整可用的。
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, embeddedFrpc, 0o600); err != nil {
		// 写不进去不致命：调用方会回退到「同目录查找」，
		// 至少还有一条路能走通。
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	// 落盘后再核一次长度：WriteFile 返回成功并不绝对等于磁盘上就是完整的那份。
	if info, err := os.Stat(tmp); err != nil || info.Size() != int64(len(embeddedFrpc)) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败：临时文件长度不一致")
	}
	// 0600：只给当前用户读写。
	//
	// 这里防的不是提权（用户本来就拥有这台机器），
	// 而是避免同一台机器上的其他账户把它替换成别的程序。
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("释放内置 frpc 失败: %w", err)
	}
	return target, nil
}
