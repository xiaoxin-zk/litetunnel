//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"syscall"
)

// reExecSelf 用新二进制替换当前进程镜像，PID 不变，systemd 无需干预。
func reExecSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
