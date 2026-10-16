package service

import "testing"

// TestIsProxyOnline 覆盖 frps 管理接口返回的 phase 取值。
//
// 这条测试对应的真实故障：代理已经注册成功、端口已经在监听，但面板把它
// 算成离线，客户端据此一直显示「连接中」。根因是状态采集只认 "running"，
// 而 frps v0.71 的管理接口返回的是 "online"。
//
// 为什么之前没被发现：CI 里没有 frps，collectTraffic 从来没跑过真实数据，
// 所以这个取值只可能在真机上暴露。因此这里把两个版本的值都钉住。
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
