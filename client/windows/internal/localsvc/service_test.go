package localsvc

import (
	"testing"
)

// TestParseNetstatTCPAndUDP 验证 TCP 与 UDP 两种行都能解析。
//
// 两者列数不同（UDP 没有状态列），按固定下标取会读错字段——
// 而错位后仍能解析出数字，不会报错，只会显示错误的端口。
func TestParseNetstatTCPAndUDP(t *testing.T) {
	out := `
活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    127.0.0.1:25565        0.0.0.0:0              LISTENING       5678
  UDP    0.0.0.0:500            *:*                                    9012
  TCP    192.168.1.5:49712      93.184.216.34:443      ESTABLISHED     3456
`
	list := ParseNetstat(out)

	if len(list) != 3 {
		t.Fatalf("应解析出 3 条监听项，实际 %d 条: %+v", len(list), list)
	}

	byPort := map[int]Service{}
	for _, s := range list {
		byPort[s.Port] = s
	}

	if s, ok := byPort[135]; !ok || s.Proto != "tcp" || s.PID != 1234 {
		t.Errorf("135/tcp 解析错误: %+v", byPort[135])
	}
	if s, ok := byPort[25565]; !ok || s.Addr != "127.0.0.1" || s.PID != 5678 {
		t.Errorf("25565 解析错误: %+v", byPort[25565])
	}
	if s, ok := byPort[500]; !ok || s.Proto != "udp" || s.PID != 9012 {
		t.Errorf("500/udp 解析错误: %+v", byPort[500])
	}

	// ESTABLISHED 是「连出去」的连接，不是本机服务，必须排除。
	// 把它列出来会让用户误以为那个端口可以映射。
	if _, ok := byPort[49712]; ok {
		t.Error("ESTABLISHED 的连接不应出现在监听列表里")
	}
}

// TestParseNetstatDeduplicatesWildcard 验证同一端口的 0.0.0.0 与 :: 两行只保留一条。
func TestParseNetstatDeduplicatesWildcard(t *testing.T) {
	out := `
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       111
  TCP    [::]:8080              [::]:0                 LISTENING       111
`
	list := ParseNetstat(out)
	if len(list) != 1 {
		t.Fatalf("重复的通配行应被去重，实际 %d 条: %+v", len(list), list)
	}
}

// TestParseTasklistKeepsColumnsAligned 验证内存列里的逗号不会让字段错位。
//
// tasklist 的内存占用形如 "12,345 K"，含逗号。按逗号切分的话
// 它会被拆成两列，PID 之后的字段全部错位——而错位后仍能解析出
// 一个「看着像 PID」的数字。
func TestParseTasklistKeepsColumnsAligned(t *testing.T) {
	out := `"svchost.exe","1234","Services","0","12,345 K"
"java.exe","5678","Console","1","1,234,567 K"
"PalServer.exe","9012","Console","1","8,888 K"
`
	names := ParseTasklist(out)

	want := map[int]string{1234: "svchost.exe", 5678: "java.exe", 9012: "PalServer.exe"}
	for pid, name := range want {
		if got := names[pid]; got != name {
			t.Errorf("PID %d 的进程名应为 %q，实际 %q", pid, name, got)
		}
	}
	if len(names) != len(want) {
		t.Errorf("应解析出 %d 个进程，实际 %d 个: %+v", len(want), len(names), names)
	}
}

// TestSplitHostPort 覆盖各种地址写法。
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  int
		valid bool
	}{
		{"0.0.0.0:135", "0.0.0.0", 135, true},
		{"127.0.0.1:25565", "127.0.0.1", 25565, true},
		{"[::]:135", "::", 135, true},
		{"[::1]:25565", "::1", 25565, true},
		{"*:*", "", 0, false},
		{"nodots", "", 0, false},
		{"0.0.0.0:0", "", 0, false},     // 端口 0 不合法
		{"0.0.0.0:99999", "", 0, false}, // 超出端口范围
	}
	for _, tc := range cases {
		host, port, ok := SplitHostPort(tc.in)
		if ok != tc.valid {
			t.Errorf("%q 的有效性应为 %v，实际 %v", tc.in, tc.valid, ok)
			continue
		}
		if !ok {
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("%q 解析为 (%q, %d)，期望 (%q, %d)", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// TestLooksUserService 验证推荐判据。
//
// 这个判据只影响排序，不影响过滤，所以断言的是「明显的两类」，
// 不去纠结边界情况——把它测得太死会阻碍以后调整权重。
func TestLooksUserService(t *testing.T) {
	// 回环地址上的一定是用户/应用自己的服务
	if !LooksUserService(135, "127.0.0.1") {
		t.Error("回环地址上的端口应被推荐")
	}
	// 高位端口多半是用户服务
	if !LooksUserService(25565, "0.0.0.0") {
		t.Error("高位端口应被推荐")
	}
	// 常见数据库端口
	if !LooksUserService(3306, "0.0.0.0") {
		t.Error("3306 应被推荐")
	}
	// Windows 系统组件端口，不能推荐——否则用户会在一堆
	// svchost 的服务里找自己要的那个
	for _, p := range []int{135, 139, 445, 5357} {
		if LooksUserService(p, "0.0.0.0") {
			t.Errorf("系统端口 %d 不应被推荐", p)
		}
	}
}

// TestSortPutsRecommendedFirst 验证排序把推荐项排在前面。
func TestSortPutsRecommendedFirst(t *testing.T) {
	list := []Service{
		{Port: 445, Proto: "tcp", Recommended: false},
		{Port: 3306, Proto: "tcp", Recommended: true},
		{Port: 135, Proto: "tcp", Recommended: false},
		{Port: 25565, Proto: "tcp", Recommended: true},
	}
	Sort(list)

	if !list[0].Recommended || !list[1].Recommended {
		t.Fatalf("推荐项应排在最前，实际顺序: %+v", list)
	}
	if list[0].Port != 3306 || list[1].Port != 25565 {
		t.Errorf("推荐项之间应按端口升序，实际: %d, %d", list[0].Port, list[1].Port)
	}
	if list[2].Port != 135 || list[3].Port != 445 {
		t.Errorf("非推荐项之间应按端口升序，实际: %d, %d", list[2].Port, list[3].Port)
	}
}

// TestParseNetstatIgnoresGarbage 验证畸形输入不会导致崩溃。
func TestParseNetstatIgnoresGarbage(t *testing.T) {
	for _, in := range []string{"", "\n\n", "活动连接", "TCP", "TCP    0.0.0.0", "a b c d e"} {
		if list := ParseNetstat(in); len(list) != 0 {
			t.Errorf("输入 %q 应解析出空列表，实际: %+v", in, list)
		}
	}
}
