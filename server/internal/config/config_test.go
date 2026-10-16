package config

import (
	"strings"
	"testing"
)

// 这个包此前没有测试。这里只守一条：**生产环境必须显式配置对外地址**。
//
// 为什么值得单独测：没有它，找回密码的重置链接只能从请求的 Host 推断域名，
// 而 Host 由请求方控制——攻击者提交伪造的 Host，链接就会指向他自己的域名
// （Host 头投毒）。这类配置缺失在开发环境完全看不出来，只有上线才暴露。

// prodEnv 返回一套「生产环境能启动」的最小配置。
func prodEnv() map[string]string {
	return map[string]string{
		"LT_ENV":                      "production",
		"LT_USER_JWT_SECRET":          strings.Repeat("a", 32),
		"LT_ADMIN_JWT_SECRET":         strings.Repeat("b", 32),
		"LT_APIKEY_ENC_KEY":           strings.Repeat("c", 32),
		"LT_BOOTSTRAP_ADMIN_PASSWORD": "Passw0rd!123",
		"LT_GATEWAY_HOST":             "gateway.example.com",
		"LT_FRPS_TOKEN":               "test-frps-token",
		"LT_FRPS_API_PASSWORD":        "test-frps-api-password",
		"LT_FRPS_PLUGIN_ALLOW_CIDR":   "127.0.0.1/32",
		"LT_USER_PUBLIC_URL":          "https://panel.example.com",
	}
}

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// TestLoadRequiresPublicURLInProduction 断言缺配置时**启动即失败**。
//
// 失败比「启动成功但发出的链接指向攻击者域名」好得多：前者一眼可见，
// 后者要等用户点了邮件里的链接才发现。
func TestLoadRequiresPublicURLInProduction(t *testing.T) {
	env := prodEnv()
	env["LT_USER_PUBLIC_URL"] = ""
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("生产环境缺少 LT_USER_PUBLIC_URL 时必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "LT_USER_PUBLIC_URL") {
		t.Fatalf("错误信息应点名缺哪一项，实际: %v", err)
	}
}

// TestLoadAcceptsProductionWithPublicURL 覆盖反面：配齐了就能启动。
func TestLoadAcceptsProductionWithPublicURL(t *testing.T) {
	setEnv(t, prodEnv())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("配置齐全时不应报错: %v", err)
	}
	if cfg.UserPublicURL != "https://panel.example.com" {
		t.Fatalf("对外地址应被读入，实际 %q", cfg.UserPublicURL)
	}
	if !cfg.IsProd() {
		t.Fatal("应识别为生产环境")
	}
}

// TestLoadWarnsWhenPublicURLMissingInDev 覆盖开发环境：不阻断启动，但必须提示。
//
// 不提示的话，用户点了「忘记密码」什么都不会发生（运行时不再从请求头推断），
// 而管理员完全不知道原因。
func TestLoadWarnsWhenPublicURLMissingInDev(t *testing.T) {
	setEnv(t, map[string]string{
		"LT_ENV":             "development",
		"LT_USER_PUBLIC_URL": "",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("开发环境不应因为缺这一项而拒绝启动: %v", err)
	}

	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "LT_USER_PUBLIC_URL") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("开发环境缺少对外地址时应给出提示，实际提示: %v", cfg.Warnings)
	}
}
