package firewall

import (
	"strings"
	"testing"
)

func TestDockerNATCompatibilityByPort(t *testing.T) {
	const raw = `{"nftables":[{"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","policy":"accept"}},{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"jump":{"target":"DOCKER"}}]}},{"rule":{"family":"ip","table":"nat","chain":"DOCKER","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},{"dnat":{"addr":"172.17.0.2","port":80}}]}}]}`
	if err := checkNftInputCompatibility([]byte(raw), nftTarget{port: 20001, proto: "tcp"}); err != nil {
		t.Fatalf("无关 Docker 端口不应阻止放行: %v", err)
	}
	if err := checkNftInputCompatibility([]byte(raw), nftTarget{port: 8080, proto: "tcp"}); err == nil {
		t.Fatal("DNAT 命中的端口必须拒绝")
	}
	if err := checkNftInputCompatibility([]byte(raw), nftTarget{port: 8080, proto: "udp"}); err != nil {
		t.Fatalf("TCP DNAT 不应阻止同端口 UDP: %v", err)
	}
	written := false
	mockFirewallCommand(t, func(_ string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-j list ruleset" {
			return raw, nil
		}
		if len(args) >= 2 && args[0] == "add" && args[1] == "rule" {
			written = true
		}
		return "", nil
	})
	if err := (&Nftables{}).AddPort(8080, "udp"); err != nil || !written {
		t.Fatalf("AddPort 必须传递 UDP 协议并允许同端口 TCP DNAT: %v", err)
	}
	udp := strings.ReplaceAll(raw, `"protocol":"tcp"`, `"protocol":"udp"`)
	if err := checkNftInputCompatibility([]byte(udp), nftTarget{port: 8080, proto: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := checkNftInputCompatibility([]byte(udp), nftTarget{port: 8080, proto: "udp"}); err == nil {
		t.Fatal("UDP DNAT 必须阻止同协议同端口")
	}
	generic := strings.ReplaceAll(raw, `"protocol":"tcp"`, `"protocol":"th"`)
	for _, proto := range []string{"tcp", "udp"} {
		if err := checkNftInputCompatibility([]byte(generic), nftTarget{port: 8080, proto: proto}); err == nil {
			t.Fatal("th 匹配必须保守视为可能冲突")
		}
	}
	withPostrouting := strings.TrimSuffix(raw, "]}") + `,{"chain":{"family":"ip","table":"nat","name":"POSTROUTING","type":"nat","hook":"postrouting","policy":"accept"}},{"rule":{"family":"ip","table":"nat","chain":"POSTROUTING","expr":[{"masquerade":null}]}}]}`
	if err := checkNftInputCompatibility([]byte(withPostrouting), nftTarget{port: 20001, proto: "tcp"}); err != nil {
		t.Fatalf("独立 POSTROUTING MASQUERADE 不应影响入站检查: %v", err)
	}
	if err := checkNftInputCompatibility([]byte(withPostrouting), nftTarget{port: 8080, proto: "tcp"}); err == nil {
		t.Fatal("忽略出站链后仍须拒绝入站 DNAT 冲突")
	}
	reachable := strings.Replace(withPostrouting, `"target":"DOCKER"`, `"target":"POSTROUTING"`, 1)
	if err := checkNftInputCompatibility([]byte(reachable), nftTarget{port: 20001, proto: "tcp"}); err == nil {
		t.Fatal("PREROUTING 可达的 MASQUERADE 仍须拒绝")
	}
	const unknown = `{"nftables":[{"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","policy":"accept"}},{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"vmap":{}}]}}]}`
	if err := checkNftInputCompatibility([]byte(unknown), nftTarget{port: 20001, proto: "tcp"}); err == nil {
		t.Fatal("未知 NAT 表达式不能放行")
	}
}
