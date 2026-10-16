package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// newTestFrps 起一个假的 frps 管理接口，返回指向它的客户端。
func newTestFrps(t *testing.T, handler http.HandlerFunc) *FrpsClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewFrpsClient(&config.Config{
		FrpsAPIAddr:     srv.URL,
		FrpsAPIUser:     "admin",
		FrpsAPIPassword: "secret",
	})
}

// frpsEnvelopeJSON 按 frps v0.71 的真实形状包一层。
//
// 分页对象在 data 里，外面还有 {code,msg}。这正是曾经被漏掉的一层：
// 直接把整个响应体当成分页对象解析时，json 不会报错，只是 Items 恒为空，
// 于是所有隧道都被判成离线，客户端一直显示「连接中」。
func frpsEnvelopeJSON(data string) string {
	return `{"code":0,"msg":"","data":` + data + `}`
}

// TestListProxiesParsesFrpsV071Envelope 是本组测试的主用例。
//
// fixture 按 frps v0.71 的真实响应抄写：分页对象包在 data 里，
// 代理名带 user 前缀，状态是 status.phase。
func TestListProxiesParsesFrpsV071Envelope(t *testing.T) {
	const body = `{
		"code": 0,
		"msg": "",
		"data": {
			"total": 2,
			"page": 1,
			"pageSize": 200,
			"items": [
				{
					"name": "lt_u1.mc",
					"user": "lt_u1",
					"clientID": "2cf2d682ced5530b",
					"status": {
						"phase": "online",
						"todayTrafficIn": 1024,
						"todayTrafficOut": 2048,
						"curConns": 3,
						"lastStartAt": 1700000000
					}
				},
				{
					"name": "lt_u1.nas",
					"user": "lt_u1",
					"clientID": "2cf2d682ced5530b",
					"status": { "phase": "closed" }
				}
			]
		}
	}`

	var authOK bool
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		authOK = ok && user == "admin" && pass == "secret"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("ListProxies 报错: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("代理数 = %d，期望 2（data 没被解开就会得到 0）", len(proxies))
	}
	if proxies[0].Name != "lt_u1.mc" {
		t.Errorf("第一条代理名 = %q，期望 lt_u1.mc", proxies[0].Name)
	}
	if proxies[0].User != "lt_u1" {
		t.Errorf("第一条代理的 user = %q，期望 lt_u1", proxies[0].User)
	}
	// 在线判定必须能从真实响应里读出来：这是客户端「运行中/连接中」的来源。
	if !IsProxyOnline(proxies[0].Status.Phase) {
		t.Errorf("phase=%q 应判为在线", proxies[0].Status.Phase)
	}
	if IsProxyOnline(proxies[1].Status.Phase) {
		t.Errorf("phase=%q 不应判为在线", proxies[1].Status.Phase)
	}
	if proxies[0].Status.TodayTrafficIn != 1024 || proxies[0].Status.TodayTrafficOut != 2048 {
		t.Errorf("流量字段没解析出来: %+v", proxies[0].Status)
	}
	if proxies[0].Status.CurConns != 3 {
		t.Errorf("curConns = %d，期望 3", proxies[0].Status.CurConns)
	}
	if !authOK {
		t.Error("没有带上 frps 管理接口的 basic auth")
	}
}

// TestListProxiesRejectsMalformedResponses 覆盖所有「读不懂响应」的情况。
//
// 共同要求只有一条：**返回错误，而不是空列表**。返回空列表会让采集器
// 把所有隧道判成离线——那正是这次故障的表现，而且日志里毫无线索。
func TestListProxiesRejectsMalformedResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"业务错误码", `{"code":1001,"msg":"invalid token","data":null}`},
		{"错误码但带 data", `{"code":7,"msg":"boom","data":{"total":0,"items":[]}}`},
		{"缺少 data", `{"code":0,"msg":""}`},
		{"data 为 null", `{"code":0,"msg":"","data":null}`},
		{"data 不是分页对象", frpsEnvelopeJSON(`"unexpected"`)},
		{"响应不是 JSON", `<html>502 Bad Gateway</html>`},
		{"裸分页对象（缺 envelope）", `{"total":1,"page":1,"pageSize":200,"items":[{"name":"lt_u1.mc"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			proxies, err := c.ListProxies(context.Background())
			if err == nil {
				t.Fatalf("应返回错误，实际拿到 %d 条代理且无错误", len(proxies))
			}
			if proxies != nil {
				t.Fatalf("出错时不应返回代理列表，实际 %d 条", len(proxies))
			}
		})
	}
}

// TestListProxiesNonOKStatusIsError 覆盖 HTTP 层错误。
func TestListProxiesNonOKStatusIsError(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"msg":"unauthorized"}`))
	})
	if _, err := c.ListProxies(context.Background()); err == nil {
		t.Fatal("非 200 状态码应返回错误")
	}
}

// TestListProxiesEmptyListIsValid 是上面那组用例的反面。
//
// 「合法但为空」必须与「读不懂」区分开：前者意味着 frps 明确告诉我们
// 当前没有任何代理（所有客户端都停了），此时把隧道判为离线才是对的。
func TestListProxiesEmptyListIsValid(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(frpsEnvelopeJSON(`{"total":0,"page":1,"pageSize":200,"items":[]}`)))
	})
	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("合法的空列表不应报错: %v", err)
	}
	if len(proxies) != 0 {
		t.Fatalf("代理数 = %d，期望 0", len(proxies))
	}
}

// TestListProxiesFollowsPagination 覆盖分页：代理数超过一页时必须继续取。
//
// 漏掉后续页的表现是「部分隧道显示离线」，比全空更难发现。
func TestListProxiesFollowsPagination(t *testing.T) {
	var mu sync.Mutex
	var pages []string

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		mu.Lock()
		pages = append(pages, page)
		mu.Unlock()

		var items []string
		switch page {
		case "1":
			for i := 0; i < 200; i++ {
				items = append(items, fmt.Sprintf(`{"name":"lt_u1.t%d","status":{"phase":"online"}}`, i))
			}
		case "2":
			items = append(items, `{"name":"lt_u1.last","status":{"phase":"online"}}`)
		}
		fmt.Fprintf(w, `{"code":0,"msg":"","data":{"total":201,"page":%s,"pageSize":200,"items":[%s]}}`,
			page, strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("ListProxies 报错: %v", err)
	}
	if len(proxies) != 201 {
		t.Fatalf("代理数 = %d，期望 201（第二页没取到就会少一条）", len(proxies))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(pages) != 2 {
		t.Fatalf("请求了 %d 页，期望 2 页", len(pages))
	}
	if proxies[200].Name != "lt_u1.last" {
		t.Fatalf("最后一条 = %q，期望 lt_u1.last", proxies[200].Name)
	}
}
