package frpc

import "testing"

func TestStripLogPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"15:28:08  Tunnel/mc  [W] [client/control.go:172] start error: boom",
			"[W] [client/control.go:172] start error: boom",
		},
		{
			"15:28:08  Tunnel/mc  两段  空格",
			"两段  空格",
		},
		{
			"15:28:08  Tunnel/mc  [W]  start error: boom",
			"[W]  start error: boom",
		},
		{"没有前缀的一行", "没有前缀的一行"},
	}
	for _, c := range cases {
		if got := StripLogPrefix(c.in); got != c.want {
			t.Errorf("StripLogPrefix(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestIsErrorLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
		why  string
	}{
		{
			"15:28:08  Tunnel/mc  [W] [client/control.go:172] [abc] [mc] start error: 隧道不存在",
			true,
			"代理启动失败（最需要显示给用户的一类）",
		},
		{
			"15:28:08  Tunnel/mc  [E] [client/service.go:312] login to server failed: i/o timeout",
			true,
			"登录失败",
		},
		{
			"15:28:08  Tunnel/mc  [I] [client/service.go:332] login to server success, get run id [abc]",
			false,
			"正常输出不该被判成错误",
		},
		{
			"15:28:08  Tunnel/mc  [I] [control.go:166] [mc] start proxy success",
			false,
			"启动成功",
		},
		{
			"15:28:08  Tunnel/errorlog  [I] [client/service.go:332] login to server success",
			false,
			"隧道名里含 error 不应误判",
		},
		{
			"15:28:08  Tunnel/failed-test  [I] [control.go:166] start proxy success",
			false,
			"隧道名里含 failed 不应误判",
		},
	}
	for _, c := range cases {
		if got := IsErrorLine(c.line); got != c.want {
			t.Errorf("IsErrorLine(%q) = %v，期望 %v（%s）", c.line, got, c.want, c.why)
		}
	}
}
