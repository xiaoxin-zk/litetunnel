package middleware

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBlockIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	blocked := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := gin.New()
	r.Use(BlockIPs(func() []netip.Prefix { return blocked }))
	r.GET("/healthz", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/api/x", func(c *gin.Context) { c.String(200, "ok") })

	do := func(path, remote string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := do("/api/x", "10.1.2.3:5555"); code != 403 {
		t.Fatalf("黑名单网段应被拒绝，实际 %d", code)
	}
	if code := do("/api/x", "8.8.8.8:5555"); code != 200 {
		t.Fatalf("正常 IP 应放行，实际 %d", code)
	}
	if code := do("/healthz", "10.1.2.3:5555"); code != 200 {
		t.Fatalf("健康检查必须放行，否则探测会误判服务已死，实际 %d", code)
	}
}

func TestBlockIPsEmptyList(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(BlockIPs(func() []netip.Prefix { return nil }))
	r.GET("/api/x", func(c *gin.Context) { c.String(200, "ok") })

	req := httptest.NewRequest("GET", "/api/x", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("未配置黑名单时不应拦截，实际 %d", w.Code)
	}
}
