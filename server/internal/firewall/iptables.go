package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ChainName 是面板专属的 iptables 链名。
//
// 所有端口放行规则都写在这条链里，再由 INPUT 跳转过来生效。
// 这样面板的规则与管理员手工添加的规则在物理上隔离：
// 面板只增删自己链内的规则，**永远不会误删别人的规则**。
const ChainName = "LT-TUNNEL"

// IPTables 通过自建链管理入站端口。
//
// 注意：iptables 规则默认不持久化，重启后丢失。
// 这不是问题——控制面启动时会按当前隧道列表重新对齐（reconcile）。
// 反过来看，这也避免了面板写坏规则后重启仍然无法连接。
type IPTables struct{}

func (t *IPTables) Name() string { return "iptables" }

func (t *IPTables) Available() bool { return hasCmd("iptables") }

// ensureChain 确保专属链存在且已从 INPUT 跳入。幂等，每次写操作前调用。
func (t *IPTables) ensureChain() error {
	if _, err := run("iptables", "-L", ChainName); err != nil {
		if _, err := run("iptables", "-N", ChainName); err != nil {
			return err
		}
	}
	if _, err := run("iptables", "-C", "INPUT", "-j", ChainName); err != nil {
		// 插到 INPUT 最前面：若 INPUT 策略为 DROP 或有前置拦截规则，
		// 追加到末尾会导致我们的放行规则永远不生效。
		if _, err := run("iptables", "-I", "INPUT", "1", "-j", ChainName); err != nil {
			return err
		}
	}
	return nil
}

// Status 判断专属链是否已建立并接入 INPUT。
//
// 只有「链不存在」能断定未启用；超时、权限不足、命令缺失都属于「查不到」，
// 必须把错误交给上层（面板据此显示「未知」）。全部吞成 false 的话，
// 一次 iptables 锁冲突就会被显示成「规则未生效」，把排查方向带偏。
func (t *IPTables) Status() (bool, error) {
	if _, err := run("iptables", "-L", ChainName); err != nil {
		if notExistErr(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := run("iptables", "-C", "INPUT", "-j", ChainName); err != nil {
		if notExistErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// 匹配 `-A LT-TUNNEL -p tcp -m tcp --dport 20001 -j ACCEPT`
var iptablesDportRe = regexp.MustCompile(`-p\s+(\w+).*--dport\s+(\d+)`)

// ListRules 列出规则。
//
// 同时读取专属链与 INPUT 的直接规则：
// 只列自己的规则会让管理员误以为「端口没放行」而重复添加，
// 这正是 1Panel issue #2945 踩过的坑。
func (t *IPTables) ListRules() ([]Rule, error) {
	var rules []Rule

	// 1) 专属链：本面板管理的规则
	if out, err := run("iptables", "-S", ChainName); err == nil {
		rules = append(rules, parseIptablesRules(out, true)...)
	}

	// 2) INPUT 上的直接放行规则：他人添加的，只读展示
	if out, err := run("iptables", "-S", "INPUT"); err == nil {
		rules = append(rules, parseIptablesRules(out, false)...)
	}

	return dedupeRules(rules), nil
}

func parseIptablesRules(out string, managed bool) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// 只关心以 -A 开头的追加规则，且目标是 ACCEPT
		if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, "-j ACCEPT") {
			continue
		}
		m := iptablesDportRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		port, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		rule := Rule{Port: port, Proto: strings.ToLower(m[1]), Managed: managed}
		if s := extractSource(line); s != "" {
			rule.Source = s
		}
		rules = append(rules, rule)
	}
	return rules
}

// extractSource 从规则里取出 -s 指定的来源网段。
func extractSource(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "-s" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// AddPort 放行端口。幂等：已存在时不重复添加。
func (t *IPTables) AddPort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	if err := t.ensureChain(); err != nil {
		return err
	}

	spec := []string{"-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	check := append([]string{"-C", ChainName}, spec...)
	if _, err := run("iptables", check...); err == nil {
		return nil
	}

	add := append([]string{"-A", ChainName}, spec...)
	_, err = run("iptables", add...)
	return err
}

// RemovePort 关闭端口。
//
// 循环删除：同一端口可能因历史原因存在多条重复规则，
// 只删一条会留下仍然生效的规则，造成「关了没关掉」的假象。
func (t *IPTables) RemovePort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}

	spec := []string{"-p", proto, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	check := append([]string{"-C", ChainName}, spec...)
	del := append([]string{"-D", ChainName}, spec...)

	for i := 0; i < 8; i++ {
		if _, err := run("iptables", check...); err != nil {
			return nil // 已不存在
		}
		if _, err := run("iptables", del...); err != nil {
			return err
		}
	}
	return fmt.Errorf("端口 %d 的规则异常重复，已删除 8 条仍未清空，请手工检查", port)
}
