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

	if err := db.Migrator().DropTable(&model.ClientSession{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	if code := call(); code == http.StatusOK {
		t.Fatal("统计查询失败时不能返回 200 + 零值：那看起来像「真的没有在线客户端」")
	}
}
