package config

import (
	"strings"
	"testing"
)

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

func TestValidateCIDRList(t *testing.T) {
	if err := validateCIDRList("LT_ADMIN_ALLOW_CIDR", nil); err != nil {
		t.Fatalf("未配置白名单不该报错: %v", err)
	}
	for _, v := range []string{"10.0.0.0/8", "1.2.3.4", "::1", "2001:db8::/32"} {
		if err := validateCIDRList("X", []string{v}); err != nil {
			t.Errorf("%s 是合法条目，不该报错: %v", v, err)
		}
	}

	cases := []struct{ name, value string }{
		{"掩码越界", "10.0.0.0/33"},
		{"多了一段", "1.2.3.4.5"},
		{"主机名不是网段", "panel.example.com"},
		{"空项", "  "},
		{"信任所有", "0.0.0.0/0"},
		{"信任所有(IPv6)", "::/0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCIDRList("LT_ADMIN_ALLOW_CIDR", []string{tc.value})
			if err == nil {
				t.Fatalf("%q 不该被接受", tc.value)
			}
			if !strings.Contains(err.Error(), "LT_ADMIN_ALLOW_CIDR") {
				t.Errorf("错误信息应点名是哪个变量，实际: %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidAllowCIDR(t *testing.T) {
	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"管理白名单拼错", "LT_ADMIN_ALLOW_CIDR", "10.0.0.0/33"},
		{"管理白名单信任所有", "LT_ADMIN_ALLOW_CIDR", "0.0.0.0/0"},
		{"插件白名单里混进一项错的", "LT_FRPS_PLUGIN_ALLOW_CIDR", "127.0.0.1/32,oops"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := prodEnv()
			env[tc.key] = tc.val
			setEnv(t, env)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q 时必须拒绝启动", tc.key, tc.val)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("错误信息应点名 %s，实际: %v", tc.key, err)
			}
		})
	}

	t.Run("开发环境也不放行", func(t *testing.T) {
		setEnv(t, map[string]string{
			"LT_ENV":              "development",
			"LT_ADMIN_ALLOW_CIDR": "10.0.0.0/33",
			"LT_USER_PUBLIC_URL":  "",
		})
		if _, err := Load(); err == nil {
			t.Fatal("非法白名单在开发环境也必须拒绝启动")
		}
	})
}

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
