package firewall

import "encoding/json"

type nftTarget struct {
	port  int
	proto string
}

func nftNATRuleSafe(expr []map[string]json.RawMessage, target nftTarget) bool {
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
				if target.proto != "" && p.Protocol != "th" && p.Protocol != target.proto {
					return true
				}
				var value int
				if json.Unmarshal(match.Right, &value) == nil && value != target.port {
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
