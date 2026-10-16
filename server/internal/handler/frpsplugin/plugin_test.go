package frpsplugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestHandleRejectsUnknownOp 覆盖插件的 fail-closed 策略。
//
// Handle 的注释写明「无法判断 op 时一律拒绝」，但 default 分支曾经是
// allow()：一个空 op、或 frps 升级后新增的操作都会静默走放行分支。
// 而「放行」在插件语义里等于**跳过鉴权**——攻击者只要能构造出我们不认识
// 的操作名，就能拿到与「凭据校验通过」相同的效果。
//
// 这类缺陷不会有任何日志、任何报错，只能靠这条断言钉住。
func TestHandleRejectsUnknownOp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 未知操作不会碰 svc，所以这里可以传 nil：
	// 一旦某天它开始依赖 svc，这条用例会立刻以 panic 的形式暴露出来。
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

// TestHandleAllowsExplicitlySafeOp 覆盖反面：明确确认过无需校验的操作
// 仍然放行。少了这条，把 default 改成拒绝之后就没人守得住
// 「NewWorkConn 必须继续放行」——它被误拒会导致已登录的客户端无法建数据通道。
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

// TestHandleRejectsMalformedBody 覆盖请求体本身解析失败的情况。
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
