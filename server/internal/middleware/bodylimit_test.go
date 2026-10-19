package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLimitBodySizeForAllowsUploadRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const normalLimit = 1 << 10
	const uploadLimit = 4 << 10

	drain := func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.String(http.StatusRequestEntityTooLarge, "读取失败: %v", err)
			return
		}
		c.String(http.StatusOK, "%d", n)
	}

	r := gin.New()
	r.Use(LimitBodySizeFor(normalLimit, map[string]int64{
		"POST /api/admin/client-packages": uploadLimit,
	}))
	r.POST("/api/admin/client-packages", drain)
	r.POST("/api/user/tunnels", drain)
	r.GET("/api/admin/client-packages", drain)

	send := func(method, path string, size int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(strings.Repeat("x", size)))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := send(http.MethodPost, "/api/admin/client-packages", uploadLimit); w.Code != http.StatusOK {
		t.Fatalf("上传路由应当放行 %d 字节，实际 %d：%s", uploadLimit, w.Code, w.Body.String())
	}
	if w := send(http.MethodPost, "/api/user/tunnels", uploadLimit); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("普通路由必须继续受 1 KiB 限制，实际 %d", w.Code)
	}
	if w := send(http.MethodGet, "/api/admin/client-packages", uploadLimit); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("例外不该按路径通配到其它方法，实际 %d", w.Code)
	}
}
