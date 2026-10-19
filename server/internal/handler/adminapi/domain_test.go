package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func newDomainTestHandler(t *testing.T) *Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:          "test",
		LogLevel:     "warn",
		DBDriver:     "sqlite",
		DBDSN:        filepath.Join(t.TempDir(), "domain.db"),
		APIKeyEncKey: "test-api-key-enc-key",
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
	t.Cleanup(svc.Close)
	return New(svc)
}

func TestDomainStatusReturnsAppliedState(t *testing.T) {
	h := newDomainTestHandler(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/domain/status", nil)
	h.DomainStatus(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200，响应体: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	for _, field := range []string{"helper", "certs", "desired", "applied", "pending"} {
		if _, ok := resp.Data[field]; !ok {
			t.Errorf("响应缺少 %q 字段：管理页会把它读成零值", field)
		}
	}

	var applied map[string]any
	if err := json.Unmarshal(resp.Data["applied"], &applied); err != nil {
		t.Fatalf("applied 应为对象: %v", err)
	}
}

func TestDomainApplyRejectsMalformedJSON(t *testing.T) {
	h := newDomainTestHandler(t)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	body := strings.NewReader(`{"apply": tru`)
	c.Request = httptest.NewRequest(http.MethodPost, "/admin/domain/apply", body)
	c.Request.Header.Set("Content-Type", "application/json")

	h.DomainApply(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应返回 400，实际 %d，响应体: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "JSON") {
		t.Errorf("错误信息应指出请求体问题，实际: %s", rec.Body.String())
	}
}
