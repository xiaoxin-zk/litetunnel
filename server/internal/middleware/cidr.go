package middleware

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CIDRSet 是预解析的网段集合，避免每次请求重复解析。
type CIDRSet struct {
	nets []*net.IPNet
	// invalid 是无法解析的原始条目。
	//
	// 必须记下来：丢弃它们会让「列表非空但一项都没解析出来」与「根本没配置」
	// 变成同一种状态，而这两者的安全含义正好相反。
	invalid []string
}

// NewCIDRSet 解析网段列表。支持 CIDR（10.0.0.0/8）与单 IP（1.2.3.4）两种写法。
//
// 解析失败的条目不会让整个集合变空，而是记进 Invalid()（见 Empty 的说明）。
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

// Invalid 返回无法解析的原始条目，供调用方在启动时记录下来。
func (s *CIDRSet) Invalid() []string {
	if s == nil {
		return nil
	}
	return s.invalid
}

// Empty 表示未配置任何网段，此时应视为「不限制」。
//
// 有解析失败的条目时**不**算空，因为那意味着「配置了白名单，但一项都没
// 认出来」。这种配置只能往拒绝的方向倒：当成「不限制」的话，一个拼错的
// CIDR 就能让管理后台对公网敞开，而界面上还显示着白名单已启用。
// （config 包会在启动时直接拒绝这种配置，这里是第二道防线。）
func (s *CIDRSet) Empty() bool {
	return s == nil || (len(s.nets) == 0 && len(s.invalid) == 0)
}

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
// 有解析失败的条目时按「已配置」处理，一律拒绝（见 Empty）；
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
