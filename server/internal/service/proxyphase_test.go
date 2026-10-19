package service

import "testing"

func TestIsProxyOnline(t *testing.T) {
	cases := []struct {
		phase string
		want  bool
		why   string
	}{
		{"online", true, "frps v0.71 管理接口实际返回的值（曾漏判）"},
		{"ONLINE", true, "大小写不该影响判定"},
		{" online ", true, "外部字符串不该因为空白被判成离线"},
		{"running", true, "较早版本 frps 用的值，必须继续认"},

		{"new", false, "刚创建，尚未注册"},
		{"wait_start", false, "等待启动"},
		{"start", false, "启动中，还没开始监听"},
		{"wait_close", false, "正在关闭"},
		{"closed", false, "已关闭"},
		{"offline", false, "明确离线"},
		{"", false, "拿不到 phase 时不能当成在线"},
	}

	for _, c := range cases {
		if got := IsProxyOnline(c.phase); got != c.want {
			t.Errorf("IsProxyOnline(%q) = %v，期望 %v（%s）", c.phase, got, c.want, c.why)
		}
	}
}
