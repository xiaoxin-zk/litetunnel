//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
)

// reExecSelf 在 Windows 上无法原地 exec：先拉起新进程，再退出当前进程。
func reExecSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动新进程失败: %w", err)
	}
	os.Exit(0)
	return nil
}
