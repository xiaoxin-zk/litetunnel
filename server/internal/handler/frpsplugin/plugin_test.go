package frpsplugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestHandleRejectsUnknownOp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := New(nil, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	cases := []struct{ name, body string }{
		{"未知操作", `{"op":"SomethingNewFromFrp","content":{}}`},
		{"空操作", `{"content":{}}`},
		{"只有版本号", `{"version":"0.71.0"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postPlugin(t, r, tc.body)
			res := decodeResponse(t, rec)
			if !res.Reject {
				t.Fatalf("%s 必须拒绝（fail-closed），实际放行: %s", tc.name, rec.Body.String())
			}
		})
	}
}

func TestHandleAllowsExplicitlySafeOp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := New(nil, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	rec := postPlugin(t, r, `{"op":"NewWorkConn","content":{}}`)
	res := decodeResponse(t, rec)
	if res.Reject {
		t.Fatalf("NewWorkConn 应放行，实际被拒: %s", rec.Body.String())
	}
	if !res.Unchange {
		t.Fatalf("放行时必须 unchange=true，否则 frp 会用空 content 覆盖原配置: %s", rec.Body.String())
	}
}

func TestNewUserConnRejectsMalformedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := New(nil, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	rec := postPlugin(t, r, `{"op":"NewUserConn","content":`)
	if res := decodeResponse(t, rec); !res.Reject {
		t.Fatalf("NewUserConn 解析失败必须拒绝，实际放行: %s", rec.Body.String())
	}
}

func TestHandleRejectsMalformedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := New(nil, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	rec := postPlugin(t, r, `{"op":`)
	if res := decodeResponse(t, rec); !res.Reject {
		t.Fatalf("解析失败必须拒绝，实际放行: %s", rec.Body.String())
	}
}

func TestDomainMatchedRequiresExactSet(t *testing.T) {
	custom := &model.Tunnel{Domain: "shop.tunnel.example.com"}
	sub := &model.Tunnel{Subdomain: "shop"}

	cases := []struct {
		name    string
		tunnel  *model.Tunnel
		content newProxyContent
		want    bool
	}{
		{"自定义域名恰好一致", custom, newProxyContent{CustomDomains: []string{"shop.tunnel.example.com"}}, true},
		{"自定义域名大小写不同", custom, newProxyContent{CustomDomains: []string{"SHOP.Tunnel.Example.COM"}}, true},
		{"追加了未授权域名", custom, newProxyContent{CustomDomains: []string{"shop.tunnel.example.com", "evil.example.com"}}, false},
		{"只报了别的域名", custom, newProxyContent{CustomDomains: []string{"evil.example.com"}}, false},
		{"一个域名都没报", custom, newProxyContent{}, false},
		{"改用子域顶替自定义域名", custom, newProxyContent{SubDomain: "shop"}, false},
		{"二级域名一致", sub, newProxyContent{SubDomain: "shop"}, true},
		{"二级域名夹带自定义域名", sub, newProxyContent{SubDomain: "shop", CustomDomains: []string{"evil.example.com"}}, false},
		{"二级域名不符", sub, newProxyContent{SubDomain: "admin"}, false},
		{"隧道既无域名也无子域", &model.Tunnel{}, newProxyContent{CustomDomains: []string{"x.example.com"}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainMatched(tc.tunnel, &tc.content); got != tc.want {
				t.Fatalf("domainMatched = %v，期望 %v", got, tc.want)
			}
		})
	}
}

func postPlugin(t *testing.T, r *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/plugin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("插件回调应始终返回 200（拒绝也走响应体），实际 %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) response {
	t.Helper()
	var res response
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("响应不是合法 JSON: %v（%s）", err, rec.Body.String())
	}
	return res
}
