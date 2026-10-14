package firewall

import (
	"bufio"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
)

// ListeningPort 描述一个正在被监听的端口。
type ListeningPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Addr 是监听地址，如 0.0.0.0 / 127.0.0.1 / ::
	Addr string `json:"addr"`
	// Exposed 表示监听在通配地址上，即对外可达
	Exposed bool `json:"exposed"`
}

// procNetFiles 是要扫描的内核网络状态文件。
//
// 直接解析 /proc 而不是调用 ss / netstat：
//   - 容器镜像里不保证装了 iproute2 或 net-tools
//   - /proc 在所有 Linux 上都存在，且读取不需要任何特权
//   - 避免为一次端口扫描引入外部依赖
var procNetFiles = []struct {
	path  string
	proto string
}{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp"},
	{"/proc/net/udp", "udp"},
	{"/proc/net/udp6", "udp"},
}

// ScanListening 扫描当前主机正在监听的端口。
//
// 用途有二：
//  1. 端口池分配时排除已被其他服务占用的端口，避免把 3306 这类端口分给用户隧道；
//  2. 管理页展示「哪些端口被系统占了」，让管理员一眼看清可用区间。
func ScanListening() ([]ListeningPort, error) {
	seen := make(map[string]bool)
	var out []ListeningPort

	for _, f := range procNetFiles {
		ports, err := parseProcNet(f.path, f.proto)
		if err != nil {
			// 单个文件读不到（如 IPv6 未启用）不应中断整体扫描
			continue
		}
		for _, p := range ports {
			key := p.Proto + "|" + strconv.Itoa(p.Port) + "|" + p.Addr
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// ListeningPortSet 返回「协议|端口」集合，供端口池快速排除。
func ListeningPortSet() map[string]bool {
	ports, err := ScanListening()
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(ports))
	for _, p := range ports {
		set[p.Proto+"|"+strconv.Itoa(p.Port)] = true
	}
	return set
}

// parseProcNet 解析 /proc/net/{tcp,tcp6,udp,udp6}。
//
// 每行格式（空白分隔）：
//
//	sl  local_address  rem_address  st  ...
//	0:  00000000:1F90  00000000:0000  0A  ...
//
// local_address 是「十六进制IP:十六进制端口」，st 是套接字状态。
func parseProcNet(path, proto string) ([]ListeningPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []ListeningPort
	scanner := bufio.NewScanner(f)
	scanner.Scan() // 跳过表头

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if !isListeningState(fields[3], proto) {
			continue
		}

		ipHex, portHex, ok := splitHexAddr(fields[1])
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		addr := decodeHexIP(ipHex, strings.HasSuffix(path, "6"))
		out = append(out, ListeningPort{
			Port:  int(port),
			Proto: proto,
			Addr:  addr,
			// 通配地址意味着对所有网卡开放，即真正对外可达
			Exposed: addr == "0.0.0.0" || addr == "::",
		})
	}
	return out, scanner.Err()
}

// isListeningState 判断套接字状态是否代表「正在监听」。
//
// TCP_LISTEN = 0A；UDP 无连接概念，07（UDP_CLOSE）即已绑定端口的空闲状态。
func isListeningState(state, proto string) bool {
	state = strings.ToUpper(state)
	if proto == "tcp" {
		return state == "0A"
	}
	return state == "07"
}

// splitHexAddr 拆出「十六进制IP」与「十六进制端口」。
func splitHexAddr(s string) (ip, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// decodeHexIP 把内核的小端十六进制地址还原成可读 IP。
func decodeHexIP(h string, v6 bool) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	if !v6 {
		if len(b) != 4 {
			return h
		}
		// /proc 中 IPv4 按小端存储，需要反转
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
	}
	if len(b) != 16 {
		return h
	}
	// IPv6 在 /proc 中按 4 字节一组、组内小端存储
	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 4 {
		parts = append(parts, hex.EncodeToString([]byte{b[i+3], b[i+2], b[i+1], b[i]}))
	}
	ip := strings.Join(parts, ":")
	// 压缩全零段，便于阅读
	ip = strings.Replace(ip, "0000:0000:0000:0000:0000:0000:0000:0000", "::", 1)
	return ip
}
