//go:build !windows

package localsvc

import "errors"

// List 在非 Windows 平台不可用。
//
// 探测依赖 netstat -ano 与 tasklist，两者的输出格式都是 Windows 专有。
// 客户端本身只构建 Windows 版本，这个分支只服务于开发者在别的系统上
// 编译调试。
//
// 返回明确错误而不是空列表：空列表在界面上表现为「本机没有正在
// 监听的服务」，那是一个会误导人的结论。
func List() ([]Service, error) {
	return nil, errors.New("本机服务探测仅在 Windows 客户端可用")
}
