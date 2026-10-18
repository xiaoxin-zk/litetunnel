package main

import (
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 这一组守的是「端口冲突必须按协议判定」。
//
// 同一个数字在 TCP 与 UDP 上是两个独立的端口空间：frps 的网关（TCP 7001）
// 与 KCP（UDP 7001）同时监听 7001 完全正常，.env.example 里就是这么写的，
// 面板侧端口池也按 "tcp|"/"udp|" 两种键记录占用。只按数字去重会把这种
// 合法配置判成冲突，管理员只能去改一个本来没问题的端口。

// validVarsForPorts 返回一份能通过前面所有校验的变量集合。
//
// 端口相关的用例只关心端口检查，其余项必须全部合法，否则会先撞上域名、
// 镜像或端口池的错误，断言就指向了错误的原因。
func validVarsForPorts() map[string]string {
	vars := baseVars()
	vars["LT_TUNNEL_DOMAIN"] = "tunnel.example.com"
	vars[tlscfg.VarDNSProvider] = "cloudflare"
	vars["LT_CADDY_IMAGE"] = "litetunnel-caddy:latest"
	vars["LT_CADDY_DNS_MODULES"] = "cloudflare"
	deriveVars(vars)
	return vars
}

// TestValidateAllowsSamePortAcrossTCPAndUDP 覆盖问题 8 的主场景：
// LT_GATEWAY_PORT 与 LT_KCP_PORT 用同一个端口号必须放行。
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

// TestValidateRejectsSamePortSameProtocol 对照组：同协议同端口仍然必须拦，
// 否则「协议化」就被理解成了「一律放宽」。
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
			// 选一个既不在端口池内、也不是 80/443 的端口。
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
			// 错误里要能看出协议，否则管理员无法判断为什么这一组算冲突、
			// 而 TCP/UDP 同号那组不算。
			if !strings.Contains(err.Error(), protoTCP) && !strings.Contains(err.Error(), protoUDP) {
				t.Errorf("错误信息应带协议，实际: %v", err)
			}
		})
	}
}

// TestValidateErrorMentionsBothProtocols 单独断言错误串的形状：
// 提示里要同时给出双方变量名与协议，管理员才知道该改哪一个。
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

// TestValidateKeepsFixedEntryNote 保留 80/443 的 allowedFixed 语义：
// vhost HTTP 可以用 80、vhost HTTPS 可以用 443，但其它变量占用 80/443 仍然不行。
func TestValidateKeepsFixedEntryNote(t *testing.T) {
	s := &service{}

	// vhost HTTP 用 80、vhost HTTPS 用 443：允许。
	vars := validVarsForPorts()
	vars["LT_VHOST_HTTP_PORT"] = "80"
	vars["LT_VHOST_HTTPS_PORT"] = "443"
	var res tlscfg.RenderResult
	if err := s.validateVars(vars, &res); err != nil {
		t.Fatalf("vhost HTTP 用 80、vhost HTTPS 用 443 应当允许: %v", err)
	}

	// 网关用 80：不允许（80 是 Caddy 的固定入口，只留给 vhost HTTP）。
	vars = validVarsForPorts()
	vars["LT_GATEWAY_PORT"] = "80"
	res = tlscfg.RenderResult{}
	if err := s.validateVars(vars, &res); err == nil {
		t.Fatal("网关占用 80 必须被拒绝")
	}

	// vhost HTTP 用 443：不允许（443 只留给 vhost HTTPS）。
	vars = validVarsForPorts()
	vars["LT_VHOST_HTTP_PORT"] = "443"
	res = tlscfg.RenderResult{}
	if err := s.validateVars(vars, &res); err == nil {
		t.Fatal("vhost HTTP 占用 443 必须被拒绝")
	}
}

// TestValidatePoolRangeCoversUDP 端口池范围检查必须对所有端口变量生效，
// 包括 UDP 的 KCP：池里的端口会被 TCP 与 UDP 两种协议同时分配。
//
// 池范围刻意只包住 KCP（7002）：若把网关也圈进去，用例会先撞上网关那条
// 错误，断言「指向 LT_KCP_PORT」就变成了空转。
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

// TestPortKeyIsProtocolScoped 是 portKey 的单元测试：
// 它一旦丢掉协议，上面所有用例都会以「看起来通过了」的方式失效。
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
