package firewall

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestScanListeningReportsRequiredTableFailure 覆盖「关键表读不到却当成没有端口在监听」。
//
// 调用方（端口池分配、空闲量统计）拿到的空集合会被理解成「没有任何端口被
// 占用」：系统占用的端口可能被分配给用户隧道（frpc 绑不上，面板却正常），
// 空闲数也会偏高。所以关键表失败必须返回错误，可选表（IPv6）缺失则不影响。
func TestScanListeningReportsRequiredTableFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc 只在 Linux 上存在；其他平台按「不支持」返回空集合")
	}

	orig := procNetFiles
	defer func() { procNetFiles = orig }()

	// 只有可选表缺失：与「没有 IPv6 监听」等价，不该报错。
	procNetFiles = []procNetFile{
		{filepath.Join(t.TempDir(), "tcp6"), "tcp", false},
	}
	if _, err := ScanListening(); err != nil {
		t.Fatalf("可选表缺失不该报错，实际 %v", err)
	}

	// 关键表缺失：必须报错。
	procNetFiles = []procNetFile{
		{filepath.Join(t.TempDir(), "tcp"), "tcp", true},
	}
	if _, err := ScanListening(); err == nil {
		t.Fatal("关键表读不到时必须返回错误，否则系统占用的端口会被当成空闲")
	}
	if _, err := ListeningPortSet(); err == nil {
		t.Fatal("集合接口同样要把错误传出去")
	}
}
