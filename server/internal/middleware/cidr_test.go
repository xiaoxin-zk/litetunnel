package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCIDRSetMatchesConfiguredNetworks(t *testing.T) {
	s := NewCIDRSet([]string{"10.0.0.0/8", "1.2.3.4", "2001:db8::/32"})

	if s.Empty() {
		t.Fatal("配置了网段就不该是空集合")
	}
	if bad := s.Invalid(); len(bad) != 0 {
		t.Fatalf("这些条目都合法，不该有解析失败项: %v", bad)
	}

	for _, ip := range []string{"10.1.2.3", "1.2.3.4", "2001:db8::1"} {
		if !s.Contains(ip) {
			t.Errorf("%s 应命中白名单", ip)
		}
	}
	for _, ip := range []string{"192.168.1.1", "1.2.3.5", "2001:db9::1"} {
		if s.Contains(ip) {
			t.Errorf("%s 不该命中白名单", ip)
		}
	}
	if s.Contains("not-an-ip") {
		t.Error("来源地址解析失败时应拒绝")
	}
}

func TestCIDRSetEmptyMeansUnrestricted(t *testing.T) {
	for _, s := range []*CIDRSet{nil, NewCIDRSet(nil), NewCIDRSet([]string{})} {
		if !s.Empty() {
			t.Fatal("未配置网段时应视为空集合")
		}
		if !s.Contains("203.0.113.9") {
			t.Error("空集合表示不限制，应当放行")
		}
	}
}

func TestCIDRSetWithOnlyInvalidEntriesDeniesAll(t *testing.T) {
	s := NewCIDRSet([]string{"10.0.0.0/33", "1.2.3.4.5"})

	if s.Empty() {
		t.Fatal("有解析失败的条目时不能算作空集合——那会让白名单静默失效")
	}
	if len(s.Invalid()) != 2 {
		t.Fatalf("解析失败的条目应被记下来，实际 %v", s.Invalid())
	}
	if s.Contains("10.1.2.3") {
		t.Error("一项都没解析出来时，任何来源都不该被放行")
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(s.Middleware())
	r.GET("/admin", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("白名单全部解析失败时必须拒绝访问，实际放行了")
	}
}

func TestCIDRSetPartiallyInvalidStillMatches(t *testing.T) {
	s := NewCIDRSet([]string{"10.0.0.0/8", "oops"})

	if s.Empty() {
		t.Fatal("有合法项时不该是空集合")
	}
	if !s.Contains("10.1.2.3") {
		t.Error("合法项应继续生效")
	}
	if s.Contains("192.168.1.1") {
		t.Error("不在合法项内的来源应被拒绝")
	}
	if len(s.Invalid()) != 1 {
		t.Fatalf("非法项应被记录，实际 %v", s.Invalid())
	}
}
