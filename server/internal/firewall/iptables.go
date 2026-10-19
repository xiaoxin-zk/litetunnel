package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const ChainName = "LT-TUNNEL"

type IPTables struct{}

func (t *IPTables) Name() string { return "iptables" }

func (t *IPTables) Available() bool { return hasCmd("iptables") }

func (t *IPTables) ensureChain() error {
	if _, err := run("iptables", "-L", ChainName); err != nil {
		if !notExistErr(err) {
			return err
		}
		if _, err := run("iptables", "-N", ChainName); err != nil {
			return err
		}
	}
	if _, err := run("iptables", "-C", "INPUT", "-j", ChainName); err != nil {
		if !notExistErr(err) {
			return err
		}
		if _, err := run("iptables", "-I", "INPUT", "1", "-j", ChainName); err != nil {
			return err
		}
	}
	return nil
}

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

var iptablesDportRe = regexp.MustCompile(`-p\s+(\w+).*--dport\s+(\d+)`)

func (t *IPTables) ListRules() ([]Rule, error) {
	var rules []Rule

	if out, err := run("iptables", "-S", ChainName); err == nil {
		rules = append(rules, parseIptablesRules(out, true)...)
	} else if !notExistErr(err) {
		return nil, err
	}

	out, err := run("iptables", "-S", "INPUT")
	if err != nil {
		return nil, err
	}
	rules = append(rules, parseIptablesRules(out, false)...)

	return dedupeRules(rules), nil
}

func parseIptablesRules(out string, managed bool) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
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

func extractSource(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "-s" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

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
	} else if !notExistErr(err) {
		return err
	}

	add := append([]string{"-A", ChainName}, spec...)
	_, err = run("iptables", add...)
	return err
}

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
			if notExistErr(err) {
				return nil
			}
			return err
		}
		if _, err := run("iptables", del...); err != nil {
			return err
		}
	}
	return fmt.Errorf("端口 %d 的规则异常重复，已删除 8 条仍未清空，请手工检查", port)
}
