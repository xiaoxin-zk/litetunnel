package router

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// TestStaticAndParamSegmentCoexist 验证同一层级可以同时注册
// 静态段（/tunnels/batch）与参数段（/tunnels/:id）。
//
// 不同版本的 gin 行为不同：早期的 httprouter 会在这种组合上直接
// panic（"wildcard route conflicts with existing children"），
// 而那是**启动时**的崩溃——一旦发生，整个服务起不来。
//
// 这类冲突无法靠读代码确认，只能实际注册一遍。
func TestStaticAndParamSegmentCoexist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("注册路由时 panic（服务器将无法启动）: %v", r)
		}
	}()

	r := gin.New()
	h := func(c *gin.Context) {}

	// 与 router.go 中 /api/user/tunnels 下注册的完整集合保持一致：
	// 少注册一条就可能漏掉真正触发冲突的那个组合。
	g := r.Group("/api/user")
	g.GET("/tunnels", h)
	g.POST("/tunnels", h)
	g.POST("/tunnels/batch", h) // ← 静态段
	g.PUT("/tunnels/:id", h)    // ← 参数段
	g.DELETE("/tunnels/:id", h)
	g.POST("/tunnels/:id/status", h)

	// 再确认路由真的能匹配上，而不只是「没 panic」
	matched := make(map[string]string)
	for _, rt := range r.Routes() {
		matched[rt.Method+" "+rt.Path] = rt.Path
	}
	for _, want := range []string{
		"POST /api/user/tunnels/batch",
		"PUT /api/user/tunnels/:id",
		"POST /api/user/tunnels/:id/status",
	} {
		if _, ok := matched[want]; !ok {
			t.Errorf("路由 %s 未注册成功", want)
		}
	}
}
