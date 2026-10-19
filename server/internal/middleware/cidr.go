package middleware

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

type CIDRSet struct {
	nets    []*net.IPNet
	invalid []string
}

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
			continue
		}
		s.invalid = append(s.invalid, c)
	}
	return s
}

func (s *CIDRSet) Invalid() []string {
	if s == nil {
		return nil
	}
	return s.invalid
}

func (s *CIDRSet) Empty() bool {
	return s == nil || (len(s.nets) == 0 && len(s.invalid) == 0)
}

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
