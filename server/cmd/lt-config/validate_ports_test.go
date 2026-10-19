package main

import (
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func validVarsForPorts() map[string]string {
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	vars[tlscfg.VarDNSProvider] = "cloudflare"
	vars["LT_CADDY_IMAGE"] = "litetunnel-caddy:latest"
	vars["LT_CADDY_DNS_MODULES"] = "cloudflare"
	deriveVars(vars)
	return vars
}

func TestValidateAllowsSamePortAcrossTCPAndUDP(t *testing.T) {
	s := &service{}
	vars := validVarsForPorts()
	vars["LT_GATEWAY_PORT"] = "7001"
	vars["LT_KCP_PORT"] = "7001"

	var res tlscfg.RenderResult
	if err := s.validateVars(vars, &res); err != nil {
		t.Fatalf("TCP 与 UDP 同号是合法配置（.env.example 明确写出），不该被拒绝: %v", err)
	}
}

func TestValidateRejectsSamePortSameProtocol(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
	}{
		{"网关与 vhost HTTP 都是 TCP", "LT_GATEWAY_PORT", "LT_VHOST_HTTP_PORT"},
		{"网关与 frps 管理端口都是 TCP", "LT_GATEWAY_PORT", "LT_FRPS_API_PORT"},
		{"网关与面板端口都是 TCP", "LT_GATEWAY_PORT", "LT_USER_PORT"},
		{"vhost HTTP 与 vhost HTTPS 都是 TCP", "LT_VHOST_HTTP_PORT", "LT_VHOST_HTTPS_PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &service{}
			vars := validVarsForPorts()
			for _, k := range []string{tc.a, tc.b} {
				vars[k] = "9001"
			}
			var res tlscfg.RenderResult
			err := s.validateVars(vars, &res)
			if err == nil {
				t.Fatalf("%s 使用同一端口 9001 时必须被拒绝", tc.name)
			}
			if !strings.Contains(err.Error(), "9001") {
				t.Errorf("错误信息应带上冲突的端口号，实际: %v", err)
			}
			if !strings.Contains(err.Error(), protoTCP) && !strings.Contains(err.Error(), protoUDP) {
				t.Errorf("错误信息应带协议，实际: %v", err)
			}
		})
	}
}

func TestValidateErrorMentionsBothProtocols(t *testing.T) {
	s := &service{}
	vars := validVarsForPorts()
	vars["LT_GATEWAY_PORT"] = "9101"
	vars["LT_VHOST_HTTP_PORT"] = "9101"

	var res tlscfg.RenderResult
	err := s.validateVars(vars, &res)
	if err == nil {
		t.Fatal("同协议同端口必须报错")
	}
	msg := err.Error()
	for _, want := range []string{"LT_GATEWAY_PORT", "LT_VHOST_HTTP_PORT", protoTCP, "9101"} {
		if !strings.Contains(msg, want) {
			t.Errorf("错误信息缺少 %q，实际: %v", want, msg)
		}
	}
}

func TestValidateKeepsFixedEntryNote(t *testing.T) {
	s := &service{}

	vars := validVarsForPorts()
	vars["LT_VHOST_HTTP_PORT"] = "80"
	vars["LT_VHOST_HTTPS_PORT"] = "443"
	var res tlscfg.RenderResult
	if err := s.validateVars(vars, &res); err != nil {
		t.Fatalf("vhost HTTP 用 80、vhost HTTPS 用 443 应当允许: %v", err)
	}

	vars = validVarsForPorts()
	vars["LT_GATEWAY_PORT"] = "80"
	res = tlscfg.RenderResult{}
	if err := s.validateVars(vars, &res); err == nil {
		t.Fatal("网关占用 80 必须被拒绝")
	}

	vars = validVarsForPorts()
	vars["LT_VHOST_HTTP_PORT"] = "443"
	res = tlscfg.RenderResult{}
	if err := s.validateVars(vars, &res); err == nil {
		t.Fatal("vhost HTTP 占用 443 必须被拒绝")
	}
}

func TestValidatePoolRangeCoversUDP(t *testing.T) {
	s := &service{}
	vars := validVarsForPorts()
	vars["LT_PORT_RANGE_START"] = "7002"
	vars["LT_PORT_RANGE_END"] = "7200"
	vars["LT_KCP_PORT"] = "7002"

	var res tlscfg.RenderResult
	err := s.validateVars(vars, &res)
	if err == nil {
		t.Fatal("KCP（UDP）端口落在端口池内同样必须被拒绝")
	}
	if !strings.Contains(err.Error(), "LT_KCP_PORT") {
		t.Errorf("错误信息应指向 LT_KCP_PORT，实际: %v", err)
	}
	if !strings.Contains(err.Error(), "7002") {
		t.Errorf("错误信息应带上端口号，实际: %v", err)
	}
}

func TestPortKeyIsProtocolScoped(t *testing.T) {
	if portKey(protoTCP, 7001) == portKey(protoUDP, 7001) {
		t.Fatal("TCP 与 UDP 的同一端口必须是不同的键")
	}
	if portKey(protoTCP, 7001) != portKey(protoTCP, 7001) {
		t.Fatal("同协议同端口必须是同一个键")
	}
	for _, k := range []string{"LT_GATEWAY_PORT", "LT_VHOST_HTTP_PORT", "LT_VHOST_HTTPS_PORT", "LT_FRPS_API_PORT", "LT_USER_PORT"} {
		if got := portProtocol[k]; got != protoTCP {
			t.Errorf("%s 应当是 TCP，实际 %q", k, got)
		}
	}
	if got := portProtocol["LT_KCP_PORT"]; got != protoUDP {
		t.Errorf("LT_KCP_PORT 是 KCP（UDP），实际 %q", got)
	}
}
