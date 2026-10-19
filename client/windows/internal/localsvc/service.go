package localsvc

import (
	"sort"
	"strconv"
	"strings"
)

type Service struct {
	Port        int    `json:"port"`
	Proto       string `json:"proto"`
	Addr        string `json:"addr"`
	PID         int    `json:"pid"`
	Process     string `json:"process"`
	Recommended bool   `json:"recommended"`
}

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
			if len(f) < 5 || !strings.EqualFold(f[3], "LISTENING") {
				continue
			}
			pid, _ = strconv.Atoi(f[4])
		} else {
			pid, _ = strconv.Atoi(f[3])
		}

		key := proto + "|" + strconv.Itoa(port) + "|" + strconv.Itoa(pid) + "|" + addrClass(host)
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

func addrClass(host string) string {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "any"
	}
	return host
}

func LooksUserService(port int, host string) bool {
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}
	if port >= 10000 {
		return true
	}
	switch port {
	case 135, 139, 445, 5040, 5357, 7680,
		1900, 3702, 5353, 5355:
		return false
	}
	switch port {
	case 3306, 5432, 6379, 27017, 8080, 8443, 8000, 9000:
		return true
	}
	return false
}

func ParseTasklist(out string) map[int]string {
	names := make(map[int]string, 128)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
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
