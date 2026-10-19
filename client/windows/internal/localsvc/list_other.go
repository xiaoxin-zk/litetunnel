//go:build !windows

package localsvc

import "errors"

func List() ([]Service, error) {
	return nil, errors.New("本机服务探测仅在 Windows 客户端可用")
}
