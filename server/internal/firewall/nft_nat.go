package firewall

import "encoding/json"

// nftNATRuleSafe 仅证明端口不匹配或规则没有改写/丢包动作，不求值任意 nft 表达式。
// 调用方仅遍历 PREROUTING 经 jump/goto 可达的链，不包含独立出站链。
func nftNATRuleSafe(expr []map[string]json.RawMessage, port int) bool {
scanMatches:
	for _, statement := range expr {
		for kind := range statement {
			if kind != "match" && kind != "counter" && kind != "comment" {
				break scanMatches
			}
		}
		var match struct {
			Op   string `json:"op"`
			Left struct {
				Payload *struct {
					Protocol string `json:"protocol"`
					Field    string `json:"field"`
				} `json:"payload"`
			} `json:"left"`
			Right json.RawMessage `json:"right"`
		}
		if raw, ok := statement["match"]; ok && json.Unmarshal(raw, &match) == nil && match.Op == "==" && match.Left.Payload != nil {
			p := match.Left.Payload
			if p.Field == "dport" && (p.Protocol == "tcp" || p.Protocol == "udp" || p.Protocol == "th") {
				var value int
				if json.Unmarshal(match.Right, &value) == nil && value != port {
					return true
				}
			}
		}
	}
	for _, statement := range expr {
		for kind := range statement {
			switch kind {
			case "match", "counter", "jump", "goto", "return", "accept", "comment":
			default:
				return false
			}
		}
	}
	return true
}
