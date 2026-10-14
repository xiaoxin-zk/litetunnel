package middleware

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CIDRSet 是预解析的网段集合，避免每次请求重复解析。
type CIDRSet struct {
	nets []*net.IPNet
}

// NewCIDRSet 解析网段列表。支持 CIDR（10.0.0.0/8）与单 IP（1.2.3.4）两种写法。
func NewCIDRSet(cidrs []string) *CIDRSet {
	s := &CIDRSet{}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			s.nets = append(s.nets, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			s.nets = append(s.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return s
}

// Empty 表示未配置任何网段，此时应视为「不限制」。
func (s *CIDRSet) Empty() bool { return s == nil || len(s.nets) == 0 }

// Contains 判断 IP 是否在集合内。
func (s *CIDRSet) Contains(ipStr string) bool {
	if s.Empty() {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Middleware 生成白名单中间件。
//
// 未配置网段时直接放行（管理后台对公网开放）；
// 命中失败时返回 404 而非 403，避免向扫描者确认该路径确实存在。
func (s *CIDRSet) Middleware() gin.HandlerFunc {
	if s.Empty() {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		if !s.Contains(c.ClientIP()) {
			c.AbortWithStatusJSON(http.StatusNotFound,
				gin.H{"code": http.StatusNotFound, "message": "资源不存在"})
			return
		}
		c.Next()
	}
}
