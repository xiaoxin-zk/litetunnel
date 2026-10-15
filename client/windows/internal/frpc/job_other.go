//go:build !windows

package frpc

import "os/exec"

// attachToJob 在非 Windows 平台上是空操作。
//
// Unix 系有「父进程退出后子进程被 init 收养」的传统，孤儿进程不会
// 遗留成用户可见的困扰；而 Windows 没有这个机制，必须显式处理。
// 保留同名函数是为了让 manager.go 里只有一条代码路径——
// 平台差异全部收敛在这两个文件里。
func attachToJob(*exec.Cmd) error { return nil }
