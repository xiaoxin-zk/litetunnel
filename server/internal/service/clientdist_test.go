package service

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeClientFileNameNormalizes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"LiteTunnel-windows-amd64.zip", "LiteTunnel-windows-amd64.zip"},
		{"  app.exe  ", "app.exe"},
		{`C:\Users\me\Desktop\LiteTunnel.exe`, "LiteTunnel.exe"},
		{"/tmp/build/pkg.deb", "pkg.deb"},
		{"pkg-1.0.tar.gz", "pkg-1.0.tar.gz"},
	}
	for _, tc := range cases {
		got, err := SanitizeClientFileName(tc.in)
		if err != nil {
			t.Errorf("输入 %q 不应被拒: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("输入 %q 归一化为 %q，期望 %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeClientFileNameNeverEscapes(t *testing.T) {
	dir := "/var/lib/litetunnel/clients"

	inputs := []string{
		"../../etc/cron.d/evil.zip",
		`..\..\windows\system32\evil.exe`,
		"....//....//evil.gz",
		"/etc/shadow.zip",
		"a/b/c/d.exe",
		"./evil.zip",
		"..%2F..%2Fevil.zip",
	}

	for _, in := range inputs {
		got, err := SanitizeClientFileName(in)
		if err != nil {
			continue
		}
		full := filepath.Join(dir, got)
		if got != filepath.Base(got) {
			t.Errorf("输入 %q 归一化为 %q，仍含目录部分", in, got)
			continue
		}
		if filepath.Dir(full) != filepath.Clean(dir) {
			t.Errorf("输入 %q 归一化为 %q，最终落在 %q（逃出了目标目录）",
				in, got, filepath.Dir(full))
		}
	}
}

func TestSanitizeClientFileNameRejects(t *testing.T) {
	bad := []struct{ in, why string }{
		{"", "空文件名"},
		{".", "当前目录"},
		{"..", "上级目录"},
		{".bashrc", "隐藏文件"},
		{"app.txt", "不在白名单的扩展名"},
		{"app.php", "脚本文件"},
		{"app.sh", "脚本文件"},
		{"app", "没有扩展名"},
		{strings.Repeat("a", 200) + ".zip", "文件名过长"},
	}
	for _, tc := range bad {
		if _, err := SanitizeClientFileName(tc.in); err == nil {
			t.Errorf("%s（%q）应被拒绝", tc.why, tc.in)
		}
	}
}

func TestSanitizeClientFileNameKeepsExtension(t *testing.T) {
	for _, name := range []string{
		"a.zip", "a.exe", "a.dmg", "a.deb", "a.rpm", "a.gz", "a.tar", "a.apk",
	} {
		if _, err := SanitizeClientFileName(name); err != nil {
			t.Errorf("%s 应被接受: %v", name, err)
		}
	}
}
