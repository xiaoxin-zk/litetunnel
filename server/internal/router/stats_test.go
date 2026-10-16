package router

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// TestStatsOverviewFailsLoudlyWhenQueryFails 覆盖「统计查询失败显示成零值」。
//
// StatsOverview 原先只检查第一个查询（总用户数），后面活跃用户、隧道、
// 在线客户端与流量都忽略错误。数据库部分故障时，那几个数字会是 0——
// 而 0 在首页上**看起来完全正常**：管理员会以为「真的没有在线客户端」，
// 而不是「数据库出了问题」。把失败当成真实的零值比直接报错更危险。
//
// 用例删掉一张**靠后**才查的表：前面的查询仍然成功，只有后面那一项失败，
// 正是原代码会静默吞掉的那种情形。
func TestStatsOverviewFailsLoudlyWhenQueryFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "stats.db"),

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := service.New(db, cfg)

	// 直接挂处理函数：本用例只关心它对查询失败的反应，
	// 鉴权与路由前缀由 router 的其它用例覆盖。
	engine := gin.New()
	engine.GET("/stats/overview", adminapi.New(svc).StatsOverview)

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/stats/overview", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(); code != http.StatusOK {
		t.Fatalf("正常情况下统计接口应返回 200，实际 %d", code)
	}

	// 删掉「在线客户端数」依赖的表：它是靠后才查的一项。
	if err := db.Migrator().DropTable(&model.ClientSession{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	if code := call(); code == http.StatusOK {
		t.Fatal("统计查询失败时不能返回 200 + 零值：那看起来像「真的没有在线客户端」")
	}
}
