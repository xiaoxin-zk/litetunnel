package firewall

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestScanListeningReportsRequiredTableFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc 只在 Linux 上存在；其他平台按「不支持」返回空集合")
	}

	orig := procNetFiles
	defer func() { procNetFiles = orig }()

	procNetFiles = []procNetFile{
		{filepath.Join(t.TempDir(), "tcp6"), "tcp", false},
	}
	if _, err := ScanListening(); err != nil {
		t.Fatalf("可选表缺失不该报错，实际 %v", err)
	}

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
