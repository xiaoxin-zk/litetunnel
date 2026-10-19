package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const managedChain = "LT-TUNNEL"

const maxRangeExpand = 1024

type iptRule struct {
	proto string
	ports []int
	src   string
	jump  string
}

func ParseIPTablesSave(dump, entryChain string) ([]Rule, error) {
	chains, rules := parseSaveDump(dump)

	if !chains[entryChain] {
		return nil, fmt.Errorf("链 %s 不存在于 iptables 规则中", entryChain)
	}

	visited := make(map[string]bool)
	var collected []Rule

	var walk func(chain string)
	walk = func(chain string) {
		if visited[chain] {
			return
		}
		visited[chain] = true

		for _, r := range rules[chain] {
			if r.jump != "" && chains[r.jump] {
				walk(r.jump)
				continue
			}
			switch strings.ToUpper(r.jump) {
			case "ACCEPT":
				collected = append(collected, r.expand(chain)...)
			case "RETURN":
				return
			}
		}
	}
	walk(entryChain)

	return dedupeRules(collected), nil
}

func dedupeRules(in []Rule) []Rule {
	best := make(map[string]Rule, len(in))
	for _, r := range in {
		key := fmt.Sprintf("%d|%s|%s", r.Port, r.Proto, r.Source)
		old, ok := best[key]
		if !ok || (r.Managed && !old.Managed) {
			best[key] = r
		}
	}

	out := make([]Rule, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func parseSaveDump(dump string) (map[string]bool, map[string][]iptRule) {
	chains := make(map[string]bool)
	rules := make(map[string][]iptRule)

	trimmed := strings.TrimSpace(dump)
	hasTableHeader := strings.HasPrefix(trimmed, "*") || strings.Contains(trimmed, "\n*")
	inFilter := !hasTableHeader

	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "*"):
			inFilter = line == "*filter"
			continue
		case line == "COMMIT":
			inFilter = false
			continue
		}
		if !inFilter {
			continue
		}

		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			if len(fields) > 0 {
				chains[fields[0]] = true
			}
			continue
		}

		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		chain := fields[1]
		rules[chain] = append(rules[chain], parseRuleFields(fields[2:]))
	}

	return chains, rules
}

func parseRuleFields(fields []string) iptRule {
	var r iptRule
	for i := 0; i < len(fields); i++ {
		next := func() (string, bool) {
			if i+1 < len(fields) {
				i++
				return fields[i], true
			}
			return "", false
		}

		switch fields[i] {
		case "-p":
			if v, ok := next(); ok {
				r.proto = strings.ToLower(v)
			}
		case "-j", "-g":
			if v, ok := next(); ok {
				r.jump = v
			}
		case "-s":
			if v, ok := next(); ok {
				r.src = v
			}
		case "--dport":
			if v, ok := next(); ok {
				r.ports = append(r.ports, parsePortSpec(v)...)
			}
		case "--dports":
			if v, ok := next(); ok {
				for _, part := range strings.Split(v, ",") {
					r.ports = append(r.ports, parsePortSpec(part)...)
				}
			}
		}
	}
	return r
}

func parsePortSpec(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	if i := strings.IndexByte(s, ':'); i > 0 {
		lo, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err1 != nil || err2 != nil || lo <= 0 || hi < lo || lo > 65535 {
			return nil
		}
		if hi > 65535 {
			hi = 65535
		}
		if hi-lo+1 > maxRangeExpand {
			hi = lo + maxRangeExpand - 1
		}
		out := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			out = append(out, p)
		}
		return out
	}

	if p, err := strconv.Atoi(s); err == nil && p > 0 && p <= 65535 {
		return []int{p}
	}
	return nil
}

func (r iptRule) expand(chain string) []Rule {
	if len(r.ports) == 0 {
		return nil
	}

	protos := []string{r.proto}
	switch r.proto {
	case "", "all", "0":
		protos = []string{"tcp", "udp"}
	}

	out := make([]Rule, 0, len(r.ports)*len(protos))
	for _, p := range r.ports {
		for _, proto := range protos {
			out = append(out, Rule{
				Port:    p,
				Proto:   proto,
				Source:  r.src,
				Chain:   chain,
				Managed: chain == managedChain,
			})
		}
	}
	return out
}
