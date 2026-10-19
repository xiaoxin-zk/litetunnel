package router

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestStaticAndParamSegmentCoexist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("注册路由时 panic（服务器将无法启动）: %v", r)
		}
	}()

	r := gin.New()
	h := func(c *gin.Context) {}

	g := r.Group("/api/user")
	g.GET("/tunnels", h)
	g.POST("/tunnels", h)
	g.POST("/tunnels/batch", h)
	g.PUT("/tunnels/:id", h)
	g.DELETE("/tunnels/:id", h)
	g.POST("/tunnels/:id/status", h)

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
