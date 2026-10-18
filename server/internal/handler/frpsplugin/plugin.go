// Package frpsplugin 实现 frps 的服务端插件回调协议。
//
// 这是整个平台的信任边界：
//   - Login     校验每用户独立凭据，拒绝伪造身份的客户端
//   - NewProxy  校验隧道归属、协议、端口，并由服务端强制下发限速
//   - NewUserConn 在超额时实时拒绝新建用户连接，实现按配额断流
//
// 协议参考 frp v0.71 的 pkg/plugin/server：请求体为
// {"version":"0.1.0","op":"Login","content":{...}}，
// 响应体为 {"reject":bool,"reject_reason":string,"unchange":bool,"content":{...}}。
//
// # 文件分工
//
// 本包按「一个问题一个文件」划分，改动准入逻辑时需要翻的地方是确定的：
//
//	plugin.go        本文件：包文档、Handler 结构、New 构造、来源网段守卫
//	dispatch.go      协议结构与 op 路由、allow/deny/modify 响应助手、
//	                 「准入状态未加载时拒绝」的通用闸门
//	identity.go      身份解析与凭据校验：resolveUser / authenticateByMeta / Login
//	session.go       会话登记与准入快照：UpsertClientSession / Ping / CloseProxy
//	plugin_proxy.go  代理准入：NewProxy（隧道归属、协议一致、服务端限速）
//	plugin_conn.go   用户连接准入：NewUserConn（断流实时拦截点）
//
// 这样分的理由：这个包的每个回调都在「要不要放行」上做决策，而这套判断
// 分布在三处（身份、会话快照、本机内存标记）。合在几个大文件里时，
// 一处加了检查、另一处忘了加，单看代码完全正常——缺陷只在特定顺序下暴露。
// 按职责拆开之后，「新加一条准入判据」有明确的落点。
package frpsplugin

import (
	"log"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type Handler struct {
	svc        *service.Services
	allowCIDRs []*net.IPNet
	// conns 按隧道限制新建连接速率，并在持续超限时短暂熔断。
	// 纯内存状态：限制针对「此刻正在发生的滥用」，不需要跨实例或跨重启。
	conns *connLimiter
}

// New 构造处理器。allowCIDRs 为允许调用本回调的来源网段。
//
// 解析失败的条目与「白名单为空」都会被记下来：前者会被静默丢弃，后者会让
// Guard 拒绝**所有**回调——表现是「隧道全部起不来」，而单条日志只有一个
// 403。启动校验（config 包）会在更早的地方拦住非法项，这里是兜底与线索。
func New(svc *service.Services, cidrs []string) *Handler {
	h := &Handler{svc: svc, conns: newConnLimiter()}
	var invalid []string
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			h.allowCIDRs = append(h.allowCIDRs, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			h.allowCIDRs = append(h.allowCIDRs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		invalid = append(invalid, c)
	}
	if len(invalid) > 0 {
		log.Printf("[plugin] LT_FRPS_PLUGIN_ALLOW_CIDR 中有 %d 项不是合法的 IP 或 CIDR: %v",
			len(invalid), invalid)
	}
	if len(h.allowCIDRs) == 0 {
		log.Printf("[plugin] 插件回调白名单为空：所有回调都会被拒绝，隧道将无法上线")
	}
	return h
}

// Guard 校验来源 IP 是否在白名单内。
//
// frp 的 HTTP 插件协议不支持自定义鉴权头，因此以「仅回环/受信网段可达」作为
// 访问控制手段：该路由只注册在管理监听地址上，不会出现在公网端口。
func (h *Handler) Guard() gin.HandlerFunc {
	return func(c *gin.Context) {
		ipStr := c.ClientIP()
		ip := net.ParseIP(ipStr)
		if ip == nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		for _, n := range h.allowCIDRs {
			if n.Contains(ip) {
				c.Next()
				return
			}
		}
		log.Printf("[plugin] 拒绝来自 %s 的插件回调请求", ipStr)
		c.AbortWithStatus(http.StatusForbidden)
	}
}
