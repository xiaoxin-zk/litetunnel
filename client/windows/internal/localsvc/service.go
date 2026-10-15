// Package localsvc 枚举本机正在监听的服务，供用户在建隧道时点选。
//
// 独立成子包而不是放在 main 里：main 包有 `//go:embed frontend/dist`，
// 没构建前端就无法编译，也就无法运行测试。而这里最容易坏掉的恰好是
// 解析逻辑——netstat 与 tasklist 的输出格式一旦变化，解析会静默地
// 返回错误结果（少了几个条目、进程名串行），不会报任何错。
// 解析能单测，这类问题才有机会被拦住。
package localsvc

import (
	"sort"
	"strconv"
	"strings"
)

// Service 是本机一个正在监听的服务。
//
// 存在的理由：用户往往**不知道自己的服务监听在哪个端口**。
// 让他手填端口，等于要求他先学会用 netstat——这是把一个
// 本该由程序解决的问题推给了用户。
type Service struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Addr 是监听地址（0.0.0.0 / 127.0.0.1 / ::）。空表示通配。
	Addr string `json:"addr"`
	// PID 与 Process 一起用于让用户辨认「这是哪个程序」。
	// 端口数字对多数用户没有意义，进程名才有。
	PID     int    `json:"pid"`
	Process string `json:"process"`
	// Recommended 表示这个端口看起来像是用户自己跑的服务（而非系统组件）。
	//
	// 判据刻意保守，只用于**排序靠前**，不用于过滤——
	// 猜错了顶多排序不理想，而过滤错了会让用户找不到自己的服务。
	Recommended bool `json:"recommended"`
}

// SplitHostPort 拆解 netstat 输出的 Local Address 列。
//
// 取值形如：0.0.0.0:135 / 127.0.0.1:25565 / [::]:135 / [::1]:25565
func SplitHostPort(s string) (host string, port int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	host = strings.Trim(s[:i], "[]")
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	if host == "*" {
		host = ""
	}
	return host, p, true
}

// ParseNetstat 解析 `netstat -ano` 的输出。
//
// 两种行的列数不同，不能按固定下标取：
//
//	TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1234     ← 5 列
//	UDP  0.0.0.0:500  *:*                   9012     ← 4 列（UDP 没有状态列）
func ParseNetstat(out string) []Service {
	seen := make(map[string]bool)
	list := make([]Service, 0, 32)

	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 4 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		host, port, ok := SplitHostPort(f[1])
		if !ok {
			continue
		}

		var pid int
		if proto == "tcp" {
			// 只收 LISTENING：ESTABLISHED 是「连出去」的连接，
			// 把它们列出来会让用户误以为那是可以映射的本机服务。
			if len(f) < 5 || !strings.EqualFold(f[3], "LISTENING") {
				continue
			}
			pid, _ = strconv.Atoi(f[4])
		} else {
			pid, _ = strconv.Atoi(f[3])
		}

		// 同一个端口常同时出现在 0.0.0.0 与 :: 两行上，只保留一条；
		// 否则列表里会出现两份一模一样的条目。
		key := proto + "|" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true

		list = append(list, Service{
			Port:        port,
			Proto:       proto,
			Addr:        host,
			PID:         pid,
			Recommended: LooksUserService(port, host),
		})
	}
	return list
}

// LooksUserService 猜测这个端口是不是用户自己跑的服务。
func LooksUserService(port int, host string) bool {
	// 系统组件极少绑在回环地址上，而用户自己的服务基本都是。
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}
	// 高位端口：用户服务最集中的区间
	if port >= 10000 {
		return true
	}
	switch port {
	case 135, 139, 445, 5040, 5357, 7680, // Windows 系统组件
		1900, 3702, 5353, 5355: // 各种服务发现协议
		return false
	}
	// 常见数据库与 Web 服务的默认端口，多半是用户自己装的
	switch port {
	case 3306, 5432, 6379, 27017, 8080, 8443, 8000, 9000:
		return true
	}
	return false
}

// ParseTasklist 解析 `tasklist /FO CSV /NH`。
//
// 每行形如（引号是 CSV 的，不属于数据）：
//
//	"svchost.exe","1234","Services","0","12,345 K"
func ParseTasklist(out string) map[int]string {
	names := make(map[int]string, 128)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 按 `","` 切分而不是按逗号：内存占用那列本身含逗号（"12,345 K"），
		// 按逗号切会把它拆成两列，后续字段全部错位。
		parts := strings.Split(line, `","`)
		if len(parts) < 2 {
			continue
		}
		name := strings.Trim(parts[0], `"`)
		pidStr := strings.Trim(parts[1], `"`)
		if name == "" {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		names[pid] = name
	}
	return names
}

// Sort 排序：推荐的在最前，然后按端口升序。
func Sort(list []Service) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Recommended != list[j].Recommended {
			return list[i].Recommended
		}
		if list[i].Port != list[j].Port {
			return list[i].Port < list[j].Port
		}
		return list[i].Proto < list[j].Proto
	})
}
