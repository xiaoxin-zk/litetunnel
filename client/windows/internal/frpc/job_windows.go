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

// attachToJob 把子进程加入一个「随本进程终止而终止」的 Job Object。
//
// # 为什么必须有它
//
// Windows 上父进程退出**不会**自动结束子进程。用户点 X 关掉客户端后，
// frpc.exe 会继续在后台跑：端口仍被占用、隧道仍然在转发，
// 而用户以为自己已经关了——既困惑，也可能在不知情的情况下继续暴露服务。
//
// # 为什么不能只靠 OnShutdown
//
// 在 OnShutdown 里调 Stop 只能覆盖「正常关闭」这一条路径。以下情况全部漏掉：
//
//   - 客户端崩溃（Wails 渲染进程或主进程异常）
//   - 被任务管理器强制结束
//   - 系统关机时进程被直接终止，来不及执行清理回调
//
// Job Object 把这交给**内核**保证：句柄随进程一起关闭，
// 子进程随之被终止。不依赖任何一段用户态清理代码被执行。
// 只覆盖正常关闭的清理逻辑，本质上是在赌「用户每次都正常关闭」。
//
// 失败不致命：调用方会退化为「仅靠 OnShutdown 清理」，
// 也就是当前行为，不会比现在更差。
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
				// 关键标志位：Job 的最后一个句柄关闭时，终止其中所有进程。
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

	// 只需要「设置配额」与「终止」权限，不申请更大的权限。
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
