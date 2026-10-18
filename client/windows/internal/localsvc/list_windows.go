//go:build windows

package localsvc

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// listCommandTimeout 是 netstat / tasklist 的单次命令超时。
//
// 这两个系统命令正常情况下瞬间返回，卡住多半是系统进入了异常状态
// （WMI 或进程枚举服务无响应）。没有超时的话，建隧道页面会一直转圈，
// 用户既不知道发生了什么，也无法取消。
const listCommandTimeout = 10 * time.Second

// List 枚举本机正在监听的服务。
//
// # 为什么用 netstat + tasklist 而不是 Windows API
//
// 准确的 API 是 GetExtendedTcpTable / GetExtendedUdpTable（iphlpapi.dll），
// 但要用它就得手写一批结构体与指针运算，且各 Windows 版本的结构体布局
// 存在差异——一旦对不上就会读到垃圾数据，而这类错误不会报错，
// 只会让界面显示一堆乱码端口，排查成本极高。
//
// netstat 与 tasklist 是 Windows 自带组件，输出格式二十年未变，
// 解析逻辑本身可以单测（见 service_test.go）。
func List() ([]Service, error) {
	raw, err := runHidden("netstat", "-ano")
	if err != nil {
		return nil, err
	}
	list := ParseNetstat(string(raw))
	if len(list) == 0 {
		return []Service{}, nil
	}

	// 进程名单独取一次，而不是按 PID 逐个查 tasklist：
	// 后者在监听项多的时候会启动几十个进程，明显卡顿。
	//
	// 取不到也不影响主流程——端口列表本身就是有用的，
	// 只是少了「这是哪个程序」这个提示。因此这里忽略错误。
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

// runHidden 执行命令并隐藏控制台窗口。
//
// 不隐藏的话每次扫描都会在用户屏幕上闪一个黑框——
// 用户会以为程序出了问题。
func runHidden(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), listCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd.Output()
}

// processNames 返回 PID → 进程名 的映射。
func processNames() (map[int]string, error) {
	raw, err := runHidden("tasklist", "/FO", "CSV", "/NH")
	if err != nil {
		return nil, err
	}
	return ParseTasklist(string(raw)), nil
}
