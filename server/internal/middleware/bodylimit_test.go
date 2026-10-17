package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestLimitBodySizeForAllowsUploadRoute 覆盖「全局 1 MiB 把上传功能悄悄关掉」。
//
// 安装包上传要几十 MB，而它走的是同一条全局中间件：上限卡在 1 MiB 时，
// 读取 FormFile 会失败，报错却只说「请求体过大」——看起来像接口坏了，
// 而不是「有一条与本意无关的通用限制挡住了它」。
//
// 反过来把全局上限抬高同样不对：那等于让每个 JSON 接口都能收几十 MB。
// 所以这里同时断言两件事：例外路由放行，普通路由照旧拒绝。
func TestLimitBodySizeForAllowsUploadRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const normalLimit = 1 << 10 // 1 KiB
	const uploadLimit = 4 << 10 // 4 KiB

	// 读满整个请求体：超限的错误只在真正读的时候才出现，这正是 FormFile
	// 在真实上传里踩到的位置。
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
	// 例外按「方法 + 路径」精确匹配：GET 同路径不该跟着放宽。
	if w := send(http.MethodGet, "/api/admin/client-packages", uploadLimit); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("例外不该按路径通配到其它方法，实际 %d", w.Code)
	}
}
