//go:build windows

package localsvc

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

const listCommandTimeout = 10 * time.Second

func List() ([]Service, error) {
	raw, err := runHidden("netstat", "-ano")
	if err != nil {
		return nil, err
	}
	list := ParseNetstat(string(raw))
	if len(list) == 0 {
		return []Service{}, nil
	}

	if names, nerr := processNames(); nerr == nil {
		for i := range list {
			if n := names[list[i].PID]; n != "" {
				list[i].Process = n
			}
		}
	}

	Sort(list)
	return list, nil
}

func runHidden(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), listCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	return cmd.Output()
}

func processNames() (map[int]string, error) {
	raw, err := runHidden("tasklist", "/FO", "CSV", "/NH")
	if err != nil {
		return nil, err
	}
	return ParseTasklist(string(raw)), nil
}
