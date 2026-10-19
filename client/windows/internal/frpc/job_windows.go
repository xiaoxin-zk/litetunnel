//go:build windows

package frpc

import (
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	jobOnce   sync.Once
	jobHandle windows.Handle
	jobErr    error
)

func attachToJob(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	jobOnce.Do(func() {
		jobHandle, jobErr = windows.CreateJobObject(nil, nil)
		if jobErr != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		_, jobErr = windows.SetInformationJobObject(
			jobHandle,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		)
	})
	if jobErr != nil {
		return jobErr
	}

	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	return windows.AssignProcessToJobObject(jobHandle, h)
}
