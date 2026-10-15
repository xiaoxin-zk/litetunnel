package firewall

import (
	"errors"
	"strings"
)

// errNoEntryChain 表示规则集里找不到任何已知的入口链。
var errNoEntryChain = errors.New("未在规则集中找到 INPUT 链")

// 入口链候选。按优先级探测：既支持传统 iptables，也支持
// 只建了 nft 兼容节点的系统。
var entryChainCandidates = []string{"INPUT"}

// SaveDump 读取当前防火墙规则集的原始文本。
//
// 优先 `iptables-save`（带表分段、格式完整），不可用时退回 `iptables -S`。
// 两者都能被 ParseIPTablesSave 解析。
func SaveDump() (string, error) {
	if hasCmd("iptables-save") {
		if out, err := run("iptables-save", "-t", "filter"); err == nil {
			return out, nil
		}
	}
	return run("iptables", "-S")
}

// ListResolvedRules 读取防火墙规则并**递归展开跳转链**，返回真正被放行的端口。
//
// 这是「只读」路径：只调用 iptables-save / iptables -S 这类查询命令，
// 不做任何修改。面板容器即便没有任何特权也能通过 helper 拿到这个结果。
func ListResolvedRules() ([]Rule, error) {
	dump, err := SaveDump()
	if err != nil {
		return nil, err
	}
	return ParseResolvedRules(dump)
}

// ParseResolvedRules 从规则集文本中解析出放行端口，自动选择合适的入口链。
func ParseResolvedRules(dump string) ([]Rule, error) {
	var lastErr error
	for _, entry := range entryChainCandidates {
		rules, err := ParseIPTablesSave(dump, entry)
		if err == nil {
			return rules, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errNoEntryChain
	}
	return nil, lastErr
}

// LookupResolved 判断某端口是否已在防火墙中放行。
//
// 用于回答「这条隧道到底通不通」——比让管理员自己去翻规则集友好得多。
func LookupResolved(port int, proto string) (bool, error) {
	rules, err := ListResolvedRules()
	if err != nil {
		return false, err
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	for _, r := range rules {
		if r.Port == port && r.Proto == proto {
			return true, nil
		}
	}
	return false, nil
}
