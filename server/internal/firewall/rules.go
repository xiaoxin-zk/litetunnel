package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// managedChain 是本面板自建的链名，用于区分「谁加的规则」。
const managedChain = "LT-TUNNEL"

// maxRangeExpand 限制端口范围的展开长度。
//
// 规则里出现 `--dport 1:65535` 是合法的，但按端口逐个展开会产出六万多条记录。
// 这类写法通常是「全放行」的意思，截断到 1024 个足以让管理员看出端倪，
// 同时避免把内存和界面撑爆。
const maxRangeExpand = 1024

// iptRule 是 iptables 规则中我们关心的字段。
//
// 只提取这些字段而不是保留整行文本：防火墙规则的行格式极其多样
// （匹配模块、注释、限速、限连接数……），保留原文会让后续判断变成
// 字符串匹配的泥潭，而面板真正需要的只有「哪个协议、哪些端口、跳去哪」。
type iptRule struct {
	proto string
	ports []int
	src   string
	jump  string
}

// ParseIPTablesSave 解析 `iptables-save` 的输出，从 entryChain 出发
// **递归展开跳转链**，给出从该链出发最终能到达哪些 ACCEPT 端口规则。
//
// # 为什么必须递归展开
//
// 真实主机上的放行规则通常不在 INPUT 里，而在被跳转过去的自定义链中：
//
//	-A INPUT  -p tcp --dport 22 -j ACCEPT
//	-A INPUT  -j DOCKER            ← 容器端口真正的放行规则在 DOCKER 链
//	-A INPUT  -j IN_BT             ← 宝塔等面板会插自己的链
//	-A DOCKER -p tcp --dport 8080 -j ACCEPT
//	-A IN_BT  -p tcp --dport 8888 -j ACCEPT
//
// 只看 INPUT 会得出「只开了 22」的错误结论。管理员据此以为端口没放行，
// 于是反复添加规则——1Panel 的 issue #2945 正是这个坑。
//
// # 静态分析的边界
//
// 这是**静态**分析：只能回答「从入口链出发，存在哪些 ACCEPT 端口规则」，
// 无法回答「某个具体数据包会不会被接受」（那取决于规则的先后顺序与
// 各种匹配条件）。用于「给管理员一个准确的现状视图」是足够的，
// 但不能拿它当安全审计的结论。
func ParseIPTablesSave(dump, entryChain string) ([]Rule, error) {
	chains, rules := parseSaveDump(dump)

	if !chains[entryChain] {
		return nil, fmt.Errorf("链 %s 不存在于 iptables 规则中", entryChain)
	}

	// 递归展开。visited 既防环（链之间可以互相跳转），也避免同一条链
	// 被多个入口重复展开而产出重复规则。
	visited := make(map[string]bool)
	var collected []Rule

	var walk func(chain string)
	walk = func(chain string) {
		if visited[chain] {
			return
		}
		visited[chain] = true

		for _, r := range rules[chain] {
			// 跳到自定义链：递归展开它。
			if r.jump != "" && chains[r.jump] {
				walk(r.jump)
				continue
			}
			switch strings.ToUpper(r.jump) {
			case "ACCEPT":
				collected = append(collected, r.expand(chain)...)
			case "RETURN":
				// 返回调用者链，本链后续规则不再参与。
				return
			}
			// DROP / REJECT / LOG / 其他目标：与「哪些端口被放行」无关，
			// 直接跳过。注意这不代表规则被忽略，只是不产出放行条目。
		}
	}
	walk(entryChain)

	return dedupeRules(collected), nil
}

// dedupeRules 按「端口 + 协议 + 来源」去重，并按端口排序。
//
// 同一条规则可能经由多条路径到达（例如 INPUT 与 FORWARD 都跳到了 DOCKER），
// 不去重的话界面上会出现重复条目，让人以为放行了两次。
//
// 若同一端口既有面板托管规则、也有系统既有规则，保留托管的那个：
// 它才是「点删除会删掉哪条」的准确答案。
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

// parseSaveDump 把 iptables-save 的输出拆成「链集合」与「每链的规则」。
//
// 只解析 *filter 表：INPUT 等内建链只存在于这张表，
// nat / mangle 表里的端口规则与「入站放行」是两回事，混进来只会误导。
func parseSaveDump(dump string) (map[string]bool, map[string][]iptRule) {
	chains := make(map[string]bool)
	rules := make(map[string][]iptRule)

	// 两种输入格式都要支持：
	//   - `iptables-save`  → 以 `*filter` 开头，需要按表分段
	//   - `iptables -S`    → 没有表头，整体就是 filter 表
	// 后者更通用：精简系统（Alpine 等）里未必装了 iptables-save，
	// 而 iptables 本体是必然存在的。
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
			// 表切换。只跟进 filter 表。
			inFilter = line == "*filter"
			continue
		case line == "COMMIT":
			inFilter = false
			continue
		}
		if !inFilter {
			continue
		}

		// 链声明：`:INPUT DROP [0:0]`
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			if len(fields) > 0 {
				chains[fields[0]] = true
			}
			continue
		}

		// 规则：`-A INPUT -p tcp --dport 22 -j ACCEPT`
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

// parseRuleFields 从规则字段中提取关心的部分。
//
// 参数可能带引号（例如 `-m comment --comment "my rule"`），
// 这里按空格切分已经足够——引号内的内容不会影响我们关心的
// -p / -j / -s / --dport 的取值。
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
			// multiport 模块：`--dports 80,443,8000:8010`
			if v, ok := next(); ok {
				for _, part := range strings.Split(v, ",") {
					r.ports = append(r.ports, parsePortSpec(part)...)
				}
			}
		}
	}
	return r
}

// parsePortSpec 解析单端口 "80" 与范围 "8000:8010" 两种写法。
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

// expand 把一条规则展开成若干「端口 + 协议」条目。
//
// 没有 --dport 的 ACCEPT 表示「全部端口放行」，这不是一条端口规则，
// 而是「这台机器不设防」——把它展开成六万条没有意义，直接忽略，
// 由界面上的链策略（INPUT 的默认动作）来体现。
func (r iptRule) expand(chain string) []Rule {
	if len(r.ports) == 0 {
		return nil
	}

	protos := []string{r.proto}
	switch r.proto {
	case "", "all", "0":
		// 未指定协议 = 同时匹配 tcp 与 udp。
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


