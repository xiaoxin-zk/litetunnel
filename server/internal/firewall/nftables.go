package firewall

import (
	"fmt"
	"regexp"
	"strconv"
)

// 面板专属的 nftables 表与链。
//
// 与 iptables 后端同理：所有规则写在自己的表里，
// 不改动系统既有的 inet filter 表，避免与管理员的手工规则互相干扰。
const (
	nftTable = "litetunnel"
	nftChain = "input"
)

// Nftables 通过自建表管理入站端口。
//
// 优先级设为 -1：保证我们的 accept 规则先于系统默认 filter 链执行，
// 否则当默认链策略为 drop 时，放行规则永远不会被命中。
type Nftables struct{}

func (n *Nftables) Name() string { return "nftables" }

func (n *Nftables) Available() bool {
	if !hasCmd("nft") {
		return false
	}
	_, err := run("nft", "list", "tables")
	return err == nil
}

func (n *Nftables) ensureTable() error {
	if _, err := run("nft", "list", "table", "inet", nftTable); err == nil {
		return nil
	}
	if _, err := run("nft", "add", "table", "inet", nftTable); err != nil {
		return err
	}
	// 链规格必须作为**单个参数**传入：它是 nft 的复合语法，
	// 拆成多个参数会被解析成不同的 token 而失败。
	spec := "{ type filter hook input priority -1 ; policy accept ; }"
	if _, err := run("nft", "add", "chain", "inet", nftTable, nftChain, spec); err != nil {
		// 链已存在（并发或上次残留）时忽略
		if _, e := run("nft", "list", "chain", "inet", nftTable, nftChain); e != nil {
			return err
		}
	}
	return nil
}

func (n *Nftables) Status() (bool, error) {
	if _, err := run("nft", "list", "chain", "inet", nftTable, nftChain); err != nil {
		return false, nil
	}
	return true, nil
}

// nftRuleRe 匹配 `tcp dport 20001 accept` 与 `udp dport 20002 accept`
var nftRuleRe = regexp.MustCompile(`(tcp|udp)\s+dport\s+(\d+)\s+accept`)

func (n *Nftables) ListRules() ([]Rule, error) {
	var rules []Rule

	if out, err := run("nft", "list", "chain", "inet", nftTable, nftChain); err == nil {
		rules = append(rules, parseNftRules(out, true)...)
	}
	// 同时读系统默认 filter 链，让管理员看到全貌（只读）
	if out, err := run("nft", "list", "chain", "inet", "filter", "input"); err == nil {
		rules = append(rules, parseNftRules(out, false)...)
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
	if err := n.ensureTable(); err != nil {
		return err
	}
	// 先检查是否已存在，保持幂等
	if n.exists(port, proto) {
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
	// 用 handle 删除：nft 只能按 handle 精确删除规则。
	// 循环若干次以清掉可能存在的重复规则。
	for i := 0; i < 8; i++ {
		handle := n.findHandle(port, proto)
		if handle == "" {
			return nil
		}
		if _, err := run("nft", "delete", "rule", "inet", nftTable, nftChain, "handle", handle); err != nil {
			return err
		}
	}
	return fmt.Errorf("端口 %d 的 nft 规则异常重复，请手工检查", port)
}

func (n *Nftables) exists(port int, proto string) bool {
	return n.findHandle(port, proto) != ""
}

// nftHandleRe 匹配带 handle 的规则行，如
// `tcp dport 20001 accept # handle 5`
var nftHandleRe = regexp.MustCompile(`(tcp|udp)\s+dport\s+(\d+)\s+accept.*#\s*handle\s+(\d+)`)

func (n *Nftables) findHandle(port int, proto string) string {
	out, err := run("nft", "-a", "list", "chain", "inet", nftTable, nftChain)
	if err != nil {
		return ""
	}
	want := strconv.Itoa(port)
	for _, m := range nftHandleRe.FindAllStringSubmatch(out, -1) {
		if m[1] == proto && m[2] == want {
			return m[3]
		}
	}
	return ""
}
