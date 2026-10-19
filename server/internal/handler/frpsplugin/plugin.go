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
	conns      *connLimiter
}

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
