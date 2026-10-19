//go:build !windows

package frpc

import "os/exec"

func attachToJob(*exec.Cmd) error { return nil }
