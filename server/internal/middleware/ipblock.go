package middleware

import (
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// BlockIPs 在鉴权之前拦掉黑名单来源，避免被封 IP 继续消耗登录失败计数与验证码资源。
// provider 返回空切片时等价于未配置，热更新通过 service 层缓存生效。
func BlockIPs(provider func() []netip.Prefix) gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/healthz") {
			c.Next()
			return
		}
		prefixes := provider()
		if len(prefixes) == 0 {
			c.Next()
			return
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(c.ClientIP()))
		if err != nil {
			c.Next()
			return
		}
		ip = ip.Unmap()
		for _, p := range prefixes {
			if p.Contains(ip) {
				httpx.Forbidden(c, "当前 IP 已被管理员封禁")
				return
			}
		}
		c.Next()
	}
}
