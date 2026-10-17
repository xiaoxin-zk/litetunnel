package firewall

import "testing"

func TestDockerNATCompatibilityByPort(t *testing.T) {
	const raw = `{"nftables":[{"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","policy":"accept"}},{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"jump":{"target":"DOCKER"}}]}},{"rule":{"family":"ip","table":"nat","chain":"DOCKER","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},{"dnat":{"addr":"172.17.0.2","port":80}}]}}]}`
	if err := checkNftInputCompatibility([]byte(raw), 20001); err != nil {
		t.Fatalf("无关 Docker 端口不应阻止放行: %v", err)
	}
	if err := checkNftInputCompatibility([]byte(raw), 8080); err == nil {
		t.Fatal("DNAT 命中的端口必须拒绝")
	}
	const unknown = `{"nftables":[{"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","policy":"accept"}},{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"vmap":{}}]}}]}`
	if err := checkNftInputCompatibility([]byte(unknown), 20001); err == nil {
		t.Fatal("未知 NAT 表达式不能放行")
	}
}
