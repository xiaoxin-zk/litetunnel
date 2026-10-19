package main

import (
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func baseVars() map[string]string {
	return map[string]string{
		"LT_GATEWAY_PORT":       "7001",
		"LT_KCP_PORT":           "7002",
		"LT_VHOST_HTTP_PORT":    "8081",
		"LT_VHOST_HTTPS_PORT":   "8444",
		"LT_FRPS_TOKEN":         "token",
		"LT_PORT_RANGE_START":   "15000",
		"LT_PORT_RANGE_END":     "32767",
		"LT_MAX_PORTS_PER_USER": "20",
		"LT_FRPS_API_PORT":      "7500",
		"LT_FRPS_API_USER":      "admin",
		"LT_FRPS_API_PASSWORD":  "pass",
		"LT_USER_PORT":          "7848",
		"LT_USER_PUBLIC_URL":    "https://panel.example.com",
	}
}

func TestValidateRejectsOfficialImageWithDNSChallenge(t *testing.T) {
	s := &service{}
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	vars[tlscfg.VarDNSProvider] = "cloudflare"
	vars["LT_CADDY_IMAGE"] = "caddy:2-alpine"
	deriveVars(vars)

	var res tlscfg.RenderResult
	err := s.validateVars(vars, &res)
	if err == nil {
		t.Fatal("官方镜像 + DNS Challenge 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "dns") {
		t.Errorf("错误信息应点明 dns 插件问题，实际: %v", err)
	}

	vars["LT_CADDY_IMAGE"] = "litetunnel-caddy:latest"
	vars["LT_CADDY_DNS_MODULES"] = "cloudflare"
	res = tlscfg.RenderResult{}
	if err := s.validateVars(vars, &res); err != nil {
		t.Fatalf("自建镜像应当通过校验: %v", err)
	}
	if len(res.RequiredPorts) < 2 {
		t.Errorf("应给出需要放行的端口，实际 %v", res.RequiredPorts)
	}
}

func TestValidateRejectsMissingTunnelProvider(t *testing.T) {
	s := &service{}
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	deriveVars(vars)

	var res tlscfg.RenderResult
	if err := s.validateVars(vars, &res); err == nil {
		t.Fatal("缺 DNS 服务商时必须被拒绝")
	}
}

func TestValidateAcceptsE2E(t *testing.T) {
	s := &service{}
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	vars[tlscfg.VarDNSProvider] = "cloudflare"
	vars["LT_CADDY_IMAGE"] = "litetunnel-caddy:latest"
	vars[tlscfg.VarHTTPSMode] = tlscfg.HTTPSModeE2E
	deriveVars(vars)

	var res tlscfg.RenderResult
	if err := s.validateVars(vars, &res); err != nil {
		t.Fatalf("端到端模式应当通过校验: %v", err)
	}
	found := false
	for _, p := range res.RequiredPorts {
		if p == 8444 {
			found = true
		}
	}
	if !found {
		t.Errorf("端到端模式必须把入口端口列入需放行清单，实际 %v", res.RequiredPorts)
	}
	if len(res.Warnings) == 0 {
		t.Error("端到端模式应提示入口端口不是 443")
	}
}

func TestValidPanelDomainAllowsPort(t *testing.T) {
	for _, ok := range []string{
		"panel.example.com",
		"203.0.113.10:7848",
		"panel.example.com:8443",
	} {
		if err := validPanelDomain(ok); err != nil {
			t.Fatalf("%q 应被判为合法: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"panel.example.com:",
		"panel.example.com:0",
		"panel.example.com:70000",
		"panel.example.com:abc",
		"panel.example.com:7848/x",
		"2001:db8::1",
	} {
		if err := validPanelDomain(bad); err == nil {
			t.Fatalf("%q 应被判为非法", bad)
		}
	}
}
