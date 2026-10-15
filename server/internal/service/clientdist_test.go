package service

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSanitizeClientFileNameNormlizes 验证正常文件名被正确归一化。
func TestSanitizeClientFileNameNormalizes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"LiteTunnel-windows-amd64.zip", "LiteTunnel-windows-amd64.zip"},
		{"  app.exe  ", "app.exe"},
		// Windows 客户端上传时可能带完整路径，必须剥掉
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

// TestSanitizeClientFileNameNeverEscapes 验证归一化结果永远落在目标目录内。
//
// 这是这个函数存在的**唯一理由**，也是唯一值得断言的安全属性：
// 文件名来自客户端、完全不可信，不处理就能写到任意系统目录。
//
// 注意「路径穿越」的两种正确处理方式都算通过：
//   - 归一化掉前缀（../../etc/x.zip → x.zip）
//   - 或者直接拒绝
//
// 唯一不可接受的是**结果逃出目标目录**。
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
			continue // 被拒绝同样可接受
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

// TestSanitizeClientFileNameRejects 验证各类非法输入被拒绝。
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

// TestSanitizeClientFileNameKeepsExtension 验证常见安装包扩展名都在白名单内。
//
// 少一个扩展名就意味着某个平台的用户拿不到客户端，而这类问题
// 不会在编译期暴露——只能靠这条断言。
func TestSanitizeClientFileNameKeepsExtension(t *testing.T) {
	for _, name := range []string{
		"a.zip", "a.exe", "a.dmg", "a.deb", "a.rpm", "a.gz", "a.tar", "a.apk",
	} {
		if _, err := SanitizeClientFileName(name); err != nil {
			t.Errorf("%s 应被接受: %v", name, err)
		}
	}
}
