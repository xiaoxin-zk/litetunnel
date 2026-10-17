package firewall

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

const (
	nftTable = "litetunnel"
	nftChain = "input"
)

type Nftables struct{}

func (n *Nftables) Name() string { return "nftables" }

func (n *Nftables) Available() bool {
	return hasCmd("nft")
}

func (n *Nftables) ensureTable() error {
	if _, err := run("nft", "list", "table", "inet", nftTable); err != nil {
		if !notExistErr(err) {
			return err
		}
		if _, err := run("nft", "add", "table", "inet", nftTable); err != nil {
			return err
		}
	}
	if _, err := run("nft", "list", "chain", "inet", nftTable, nftChain); err == nil {
		return nil
	} else if !notExistErr(err) {
		return err
	}
	spec := "{ type filter hook input priority -1 ; policy accept ; }"
	_, err := run("nft", "add", "chain", "inet", nftTable, nftChain, spec)
	return err
}

func (n *Nftables) compatible(target ...int) error {
	out, err := run("nft", "-j", "list", "ruleset")
	if err != nil {
		return err
	}
	return checkNftInputCompatibility([]byte(out), target...)
}

type nftChainSpec struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

func checkNftInputCompatibility(raw []byte, target ...int) error {
	var dump struct {
		Objects []struct {
			Chain *nftChainSpec `json:"chain"`
			Rule  *struct {
				Family string                       `json:"family"`
				Table  string                       `json:"table"`
				Chain  string                       `json:"chain"`
				Expr   []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return fmt.Errorf("解析 nftables 规则集失败: %w", err)
	}
	if dump.Objects == nil {
		return fmt.Errorf("nftables 规则集缺少 nftables 数组")
	}
	key := func(family, table, chain string) string { return family + "/" + table + "/" + chain }
	rules := make(map[string]int)
	for _, object := range dump.Objects {
		if r := object.Rule; r != nil {
			rules[key(r.Family, r.Table, r.Chain)]++
		}
	}
	for _, object := range dump.Objects {
		c := object.Chain
		if c == nil {
			continue
		}
		owned := c.Family == "inet" && c.Table == nftTable && c.Name == nftChain
		if owned {
			if c.Type != "filter" || c.Hook != "input" || c.Policy != "accept" {
				return fmt.Errorf("nftables 专属链规格不兼容，未修改规则")
			}
			continue
		}
		if c.Type == "nat" && c.Hook == "prerouting" && c.Policy == "accept" && (c.Family == "ip" || c.Family == "ip6" || c.Family == "inet") {
			if len(target) > 0 {
				for _, object := range dump.Objects {
					r := object.Rule
					if r != nil && r.Family == c.Family && r.Table == c.Table && !nftNATRuleSafe(r.Expr, target[0]) {
						return fmt.Errorf("nftables NAT 表 %s/%s 可能改写或拦截端口 %d，未修改规则", c.Family, c.Table, target[0])
					}
				}
			}
			continue
		}
		if c.Hook != "" && (c.Family == "bridge" || c.Family == "netdev" || c.Hook == "ingress" || c.Hook == "prerouting") {
			return fmt.Errorf("nftables 基链 %s 使用不支持的 %s hook，无法保证入站放行生效，未修改规则", key(c.Family, c.Table, c.Name), c.Hook)
		}
		if c.Hook != "input" || (c.Family != "inet" && c.Family != "ip" && c.Family != "ip6") {
			continue
		}
		// 独立基链中的 accept 不能覆盖其他基链的 drop；非空链可能包含跳转、
		// verdict map 或条件拒绝。未实现完整求值时，仅接受空的 accept 基链。
		if c.Type != "filter" || c.Policy != "accept" || rules[key(c.Family, c.Table, c.Name)] != 0 {
			return fmt.Errorf("nftables input 基链 %s 不兼容：无法保证专属链的放行生效，请由现有防火墙管理器放行端口", key(c.Family, c.Table, c.Name))
		}
	}
	return nil
}

func (n *Nftables) Status() (bool, error) {
	if err := n.compatible(); err != nil {
		return false, err
	}
	if _, err := run("nft", "list", "chain", "inet", nftTable, nftChain); err != nil {
		if notExistErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

var nftRuleRe = regexp.MustCompile(`(tcp|udp)\s+dport\s+(\d+)\s+accept`)

func (n *Nftables) ListRules() ([]Rule, error) {
	var rules []Rule
	for _, chain := range []struct {
		table, name string
		managed     bool
	}{
		{nftTable, nftChain, true},
		{"filter", "input", false},
	} {
		out, err := run("nft", "list", "chain", "inet", chain.table, chain.name)
		if err != nil {
			if notExistErr(err) {
				continue
			}
			return nil, err
		}
		rules = append(rules, parseNftRules(out, chain.managed)...)
	}
	return dedupeRules(rules), nil
}

func parseNftRules(out string, managed bool) []Rule {
	var rules []Rule
	for _, m := range nftRuleRe.FindAllStringSubmatch(out, -1) {
		port, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		rules = append(rules, Rule{Port: port, Proto: m[1], Managed: managed})
	}
	return rules
}

func (n *Nftables) AddPort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	if err := n.compatible(port); err != nil {
		return err
	}
	if err := n.ensureTable(); err != nil {
		return err
	}
	handle, err := n.findHandle(port, proto)
	if err != nil {
		return err
	}
	if handle != "" {
		return nil
	}
	_, err = run("nft", "add", "rule", "inet", nftTable, nftChain,
		proto, "dport", strconv.Itoa(port), "accept")
	return err
}

func (n *Nftables) RemovePort(port int, proto string) error {
	proto, err := normalizeProto(proto)
	if err != nil {
		return err
	}
	for i := 0; i < 8; i++ {
		handle, err := n.findHandle(port, proto)
		if err != nil {
			return err
		}
		if handle == "" {
			return nil
		}
		if _, err := run("nft", "delete", "rule", "inet", nftTable, nftChain, "handle", handle); err != nil {
			return err
		}
	}
	return fmt.Errorf("端口 %d 的 nft 规则异常重复，请手工检查", port)
}

var nftHandleRe = regexp.MustCompile(`(tcp|udp)\s+dport\s+(\d+)\s+accept.*#\s*handle\s+(\d+)`)

func (n *Nftables) findHandle(port int, proto string) (string, error) {
	out, err := run("nft", "-a", "list", "chain", "inet", nftTable, nftChain)
	if err != nil {
		if notExistErr(err) {
			return "", nil
		}
		return "", err
	}
	want := strconv.Itoa(port)
	for _, m := range nftHandleRe.FindAllStringSubmatch(out, -1) {
		if m[1] == proto && m[2] == want {
			return m[3], nil
		}
	}
	return "", nil
}
