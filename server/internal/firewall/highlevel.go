package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ---- ufw（Ubuntu / Debian 默认）----

// UFW 通过 ufw 命令管理端口。
//
// ufw 不是链式模型，而是「允许/拒绝某端口」的高层语义，
// 因此这里直接用它的 allow/delete 子命令，不介入底层的 iptables。
// 好处是 ufw 自己维护规则文件，重启后依然生效。
type UFW struct{}

func (u *UFW) Name() string { return "ufw" }

// Available 判断 ufw 是否可用。
//
// 只判断命令存在是不够的：容器里可能装了 ufw 但没有内核权限，
// 因此再执行一次无副作用的 status 确认能真正跑起来。
func (u *UFW) Available() bool {
	if !hasCmd("ufw") {
		return false
	}
	_, err := run("ufw", "status")
	return err == nil
}

func (u *UFW) Status() (bool, error) {
	out, err := run("ufw", "status")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "Status: active"), nil
}

// ufwRuleRe 匹配 `20001/tcp   ALLOW   Anywhere` 这类规则行。
var ufwRuleRe = regexp.MustCompile(`(?m)^\s*(\d+)/(tcp|udp)\s+ALLOW`)

func (u *UFW) ListRules() ([]Rule, error) {
	out, err := run("ufw", "status")
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, m := range ufwRuleRe.FindAllStringSubmatch(out, -1) {
		port, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		// ufw 的规则由 ufw 自己管理，统一视为「面板可见但不属于专属链」。
		rules = append(rules, Rule{Port: port, Proto: m[2], Managed: false})
	}
	return dedupeRules(rules), nil
}

func (u *UFW) AddPort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	// ufw allow 对同一规则是幂等的，重复执行不会报错也不会产生重复条目。
	_, err = run("ufw", "allow", fmt.Sprintf("%d/%s", port, proto))
	return err
}

func (u *UFW) RemovePort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	out, err := run("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto))
	if err != nil {
		// 规则本就不存在时 ufw 会返回错误，这不是故障。
		if strings.Contains(out, "Could not delete non-existent rule") {
			return nil
		}
		return err
	}
	return nil
}

// ---- firewalld（CentOS / RHEL / Rocky 默认）----

// Firewalld 通过 firewall-cmd 管理端口。
//
// 只操作 public 区域的端口列表，不碰 zone / service / rich rule，
// 避免与管理员既有的区域划分策略冲突。
type Firewalld struct{}

func (f *Firewalld) Name() string { return "firewalld" }

func (f *Firewalld) Available() bool {
	if !hasCmd("firewall-cmd") {
		return false
	}
	_, err := run("firewall-cmd", "--state")
	return err == nil
}

func (f *Firewalld) Status() (bool, error) {
	out, err := run("firewall-cmd", "--state")
	if err != nil {
		return false, nil
	}
	return strings.Contains(out, "running"), nil
}

// firewalldPortRe 匹配 `20001/tcp` 形式的端口项。
var firewalldPortRe = regexp.MustCompile(`(\d+)/(tcp|udp)`)

func (f *Firewalld) ListRules() ([]Rule, error) {
	// 读 permanent 配置：--list-ports 只反映运行时状态，
	// 而运行时可能尚未 reload，会漏掉刚写入的永久规则。
	out, err := run("firewall-cmd", "--list-ports", "--permanent")
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, m := range firewalldPortRe.FindAllStringSubmatch(out, -1) {
		port, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		rules = append(rules, Rule{Port: port, Proto: m[2], Managed: false})
	}
	return dedupeRules(rules), nil
}

func (f *Firewalld) AddPort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	spec := fmt.Sprintf("%d/%s", port, proto)
	if _, err := run("firewall-cmd", "--add-port", spec, "--permanent"); err != nil {
		return err
	}
	// 必须 reload 才会生效；--permanent 只写配置不改运行时。
	_, err = run("firewall-cmd", "--reload")
	return err
}

func (f *Firewalld) RemovePort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	spec := fmt.Sprintf("%d/%s", port, proto)
	if _, err := run("firewall-cmd", "--remove-port", spec, "--permanent"); err != nil {
		// 不存在时 firewalld 会报 NOT_ENABLED / INVALID_RULE，按已删除处理。
		if strings.Contains(err.Error(), "NOT_ENABLED") {
			return nil
		}
		return err
	}
	_, err = run("firewall-cmd", "--reload")
	return err
}
