package config

import "testing"

// LT_FRPS_API_ADDR 写错时，采集与断流会在运行期持续失败，而启动日志里
// 看不出来。这里守住「必须在启动时就拒绝」的那几种写法。
func TestValidateNumericEnvsRejectsMalformedAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"带 scheme", "http://127.0.0.1:7500"},
		{"带 userinfo", "admin:pass@127.0.0.1:7500"},
		{"带 query", "127.0.0.1:7500?x=1"},
		{"带 fragment", "127.0.0.1:7500#x"},
		{"缺少端口", "127.0.0.1"},
		{"端口越界", "127.0.0.1:70000"},
		{"端口非数字", "127.0.0.1:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LT_FRPS_API_ADDR", tc.addr)
			if err := validateNumericEnvs(); err == nil {
				t.Fatalf("%q 应在启动时被拒绝", tc.addr)
			}
		})
	}

	t.Setenv("LT_FRPS_API_ADDR", "127.0.0.1:7500")
	if err := validateNumericEnvs(); err != nil {
		t.Fatalf("合法地址不应被拒绝: %v", err)
	}
}

// 端口类变量必须落在 1-65535：只校验「能 Atoi」会放过 0 与 70000。
func TestValidateNumericEnvsRejectsOutOfRangePort(t *testing.T) {
	t.Setenv("LT_GATEWAY_PORT", "70000")
	if err := validateNumericEnvs(); err == nil {
		t.Fatal("超出范围的端口应被拒绝")
	}
}
