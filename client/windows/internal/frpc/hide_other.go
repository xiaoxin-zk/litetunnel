//go:build !windows

package frpc

import "os/exec"

func hideWindow(_ *exec.Cmd) {}
