package firewall

import (
	"errors"
	"strings"
)

var errNoEntryChain = errors.New("未在规则集中找到 INPUT 链")

var entryChainCandidates = []string{"INPUT"}

func SaveDump() (string, error) {
	if hasCmd("iptables-save") {
		if out, err := run("iptables-save", "-t", "filter"); err == nil {
			return out, nil
		}
	}
	return run("iptables", "-S")
}

func ListResolvedRules() ([]Rule, error) {
	dump, err := SaveDump()
	if err != nil {
		return nil, err
	}
	return ParseResolvedRules(dump)
}

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
