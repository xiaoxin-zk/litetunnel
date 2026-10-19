package firewall

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func LocalPortRange() (start, end int, err error) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("无法解析出站端口范围: %q", strings.TrimSpace(string(raw)))
	}
	lo, err1 := strconv.Atoi(fields[0])
	hi, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || lo <= 0 || hi <= lo {
		return 0, 0, fmt.Errorf("出站端口范围取值异常: %q", strings.TrimSpace(string(raw)))
	}
	return lo, hi, nil
}

type ListeningPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Exposed bool   `json:"exposed"`
}

type procNetFile struct {
	path     string
	proto    string
	required bool
}

var procNetFiles = []procNetFile{
	{"/proc/net/tcp", "tcp", true},
	{"/proc/net/tcp6", "tcp", false},
	{"/proc/net/udp", "udp", true},
	{"/proc/net/udp6", "udp", false},
}

func ScanListening() ([]ListeningPort, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var out []ListeningPort

	for _, f := range procNetFiles {
		ports, err := parseProcNet(f.path, f.proto)
		if err != nil {
			if f.required {
				return nil, fmt.Errorf("读取 %s 失败: %w", f.path, err)
			}
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

func ListeningPortSet() (map[string]bool, error) {
	ports, err := ScanListening()
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ports))
	for _, p := range ports {
		set[p.Proto+"|"+strconv.Itoa(p.Port)] = true
	}
	return set, nil
}

func parseProcNet(path, proto string) ([]ListeningPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []ListeningPort
	scanner := bufio.NewScanner(f)
	scanner.Scan()

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
			Port:    int(port),
			Proto:   proto,
			Addr:    addr,
			Exposed: addr == "0.0.0.0" || addr == "::",
		})
	}
	return out, scanner.Err()
}

func isListeningState(state, proto string) bool {
	state = strings.ToUpper(state)
	if proto == "tcp" {
		return state == "0A"
	}
	return state == "07"
}

func splitHexAddr(s string) (ip, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func decodeHexIP(h string, v6 bool) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	if !v6 {
		if len(b) != 4 {
			return h
		}
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
	}
	if len(b) != 16 {
		return h
	}
	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 4 {
		parts = append(parts, hex.EncodeToString([]byte{b[i+3], b[i+2], b[i+1], b[i]}))
	}
	ip := strings.Join(parts, ":")
	ip = strings.Replace(ip, "0000:0000:0000:0000:0000:0000:0000:0000", "::", 1)
	return ip
}
