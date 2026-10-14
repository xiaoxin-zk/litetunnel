//go:build !windows

package frpc

import "os/exec"

// hideWindow 在非 Windows 平台无需处理窗口隐藏。
func hideWindow(_ *exec.Cmd) {}
