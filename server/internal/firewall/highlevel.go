package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type UFW struct{}

func (u *UFW) Name() string { return "ufw" }

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
		rules = append(rules, Rule{Port: port, Proto: m[2], Managed: false})
	}
	return dedupeRules(rules), nil
}

func (u *UFW) AddPort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
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
		if strings.Contains(out, "Could not delete non-existent rule") {
			return nil
		}
		return err
	}
	return nil
}

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
		if notExistErr(err) {
			return false, nil
		}
		return false, err
	}
	return strings.Contains(out, "running"), nil
}

var firewalldPortRe = regexp.MustCompile(`(\d+)/(tcp|udp)`)

func (f *Firewalld) ListRules() ([]Rule, error) {
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
		if strings.Contains(err.Error(), "NOT_ENABLED") {
			return nil
		}
		return err
	}
	_, err = run("firewall-cmd", "--reload")
	return err
}
