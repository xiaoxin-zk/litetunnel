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

// frpsOK 按 frps v0.71 的**真实**成功响应包一层。
//
// 成功码是 200，不是 0。这个细节必须由 fixture 如实反映：上一版实现按
// `code != 0` 判错，而 fixture 又全用 `code:0`，于是「把成功当失败」这个
// 缺陷被测试完美地掩盖了——测试全绿，线上一条隧道也显示不了在线。
func frpsOK(data string) string {
	return `{"code":200,"msg":"success","data":` + data + `}`
}

// TestListProxiesParsesFrpsV071Response 是本组测试的主用例。
//
// fixture 逐字来自线上 frps v0.71 的实测响应：成功码 200，分页对象包在
// data 里，代理名带 user 前缀，状态在 status.phase。
func TestListProxiesParsesFrpsV071Response(t *testing.T) {
	const body = `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":"lt_u1.mc","status":{"phase":"online"}}]}}`

	var authOK bool
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		authOK = ok && user == "admin" && pass == "secret"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})

	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("线上实测响应必须能解析，实际报错: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("代理数 = %d，期望 1", len(proxies))
	}
	if proxies[0].Name != "lt_u1.mc" {
		t.Errorf("代理名 = %q，期望 lt_u1.mc", proxies[0].Name)
	}
	// 这一条就是客户端「运行中/连接中」的来源。
	if !IsProxyOnline(proxies[0].Status.Phase) {
		t.Errorf("phase=%q 应判为在线", proxies[0].Status.Phase)
	}
	if !authOK {
		t.Error("没有带上 frps 管理接口的 basic auth")
	}
}

// TestListProxiesParsesFullProxyFields 覆盖代理对象的各个字段。
func TestListProxiesParsesFullProxyFields(t *testing.T) {
	body := frpsOK(`{"total":2,"page":1,"pageSize":200,"items":[
		{"name":"lt_u1.mc","user":"lt_u1","clientID":"2cf2d682ced5530b",
		 "status":{"phase":"online","todayTrafficIn":1024,"todayTrafficOut":2048,"curConns":3,"lastStartAt":1700000000}},
		{"name":"lt_u1.nas","user":"lt_u1","clientID":"2cf2d682ced5530b",
		 "status":{"phase":"closed"}}
	]}`)

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("ListProxies 报错: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("代理数 = %d，期望 2", len(proxies))
	}
	if proxies[0].User != "lt_u1" || proxies[0].ClientID != "2cf2d682ced5530b" {
		t.Errorf("user/clientID 没解析出来: %+v", proxies[0])
	}
	if proxies[0].Status.TodayTrafficIn != 1024 || proxies[0].Status.TodayTrafficOut != 2048 {
		t.Errorf("流量字段没解析出来: %+v", proxies[0].Status)
	}
	if proxies[0].Status.CurConns != 3 || proxies[0].Status.LastStartAt != 1700000000 {
		t.Errorf("运行态字段没解析出来: %+v", proxies[0].Status)
	}
	if IsProxyOnline(proxies[1].Status.Phase) {
		t.Errorf("phase=%q 不应判为在线", proxies[1].Status.Phase)
	}
}

// TestListProxiesAcceptsSuccessCodeWithoutMsg 覆盖成功码 + 缺 msg。
//
// msg 只是给人看的字符串，缺失不影响成功判定；code 缺失才致命。
func TestListProxiesAcceptsSuccessCodeWithoutMsg(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"page":1,"pageSize":200,"items":[]}}`))
	})
	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("成功码 + 缺 msg 不应报错: %v", err)
	}
	if len(proxies) != 0 {
		t.Fatalf("代理数 = %d，期望 0", len(proxies))
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
		{"非成功码（401）", `{"code":401,"msg":"unauthorized","data":null}`},
		{"非成功码但带 data", `{"code":1001,"msg":"invalid token","data":{"total":0,"items":[]}}`},
		// 曾经把 code 解成普通 int，缺字段默认成 0；如果 data 恰好合法
		// 就会被当成成功放行，而我们对这份响应其实一无所知。
		{"缺 code 但有合法 data", `{"msg":"success","data":{"total":0,"items":[]}}`},
		{"code 为 null", `{"code":null,"data":{"total":0,"items":[]}}`},
		// frps 的成功码是 200，0 不是成功码。
		{"code 为 0", `{"code":0,"msg":"","data":{"total":0,"items":[]}}`},
		{"缺 data", `{"code":200,"msg":"success"}`},
		{"data 为 null", `{"code":200,"msg":"success","data":null}`},
		{"data 不是分页对象", frpsOK(`"unexpected"`)},
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
		_, _ = w.Write([]byte(frpsOK(`{"total":0,"page":1,"pageSize":200,"items":[]}`)))
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
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":201,"page":%s,"pageSize":200,"items":[%s]}}`,
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

// TestListProxiesRejectsShortPageWithRemainingTotal 覆盖「短页但 total 未满足」。
//
// frps 报 total=350 却在第 100 条处提前结束：短页原先会被当成「读完了」，
// 没读到的 250 条凭空消失，采集器把那些隧道判成离线。必须报错，
// 让调用方保住上一轮的在线状态。
func TestListProxiesRejectsShortPageWithRemainingTotal(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		items := make([]string, 0, 100)
		for i := 0; i < 100; i++ {
			items = append(items, `{"name":"lt_u1.x","status":{"phase":"online"}}`)
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":350,"page":1,"pageSize":200,"items":[%s]}}`,
			strings.Join(items, ","))
	})
	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("短页且 total 未满足应报错，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("结果不完整时不应返回代理列表")
	}
	if !strings.Contains(err.Error(), "不完整") {
		t.Fatalf("错误信息应说明列表不完整，实际: %v", err)
	}
}

// TestListProxiesRejectsMissingTotalWithShortPage 覆盖「total 缺失 + 短页」。
//
// total 缺失会被解码成 0，任何短页原先都「满足完成条件」。
// 除「total=0 且整页为空」这个明确的空列表外，一律不采信。
func TestListProxiesRejectsMissingTotalWithShortPage(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","data":{"page":1,"pageSize":200,"items":[{"name":"lt_u1.mc","status":{"phase":"online"}}]}}`))
	})
	if _, err := c.ListProxies(context.Background()); err == nil {
		t.Fatal("total 缺失且页面非满时应报错")
	}
}

// TestListProxiesRejectsPageCapOverflow 覆盖分页上限。
//
// 取满上限仍有数据时必须报错：悄悄返回一份不完整的列表，会让没读到的
// 那些隧道被判成离线，而日志里看不出是分页被截断导致的。
func TestListProxiesRejectsPageCapOverflow(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()

		// 每一页都返回满页，total 远大于能取到的数量。
		items := make([]string, 0, 200)
		for i := 0; i < 200; i++ {
			items = append(items, `{"name":"lt_u1.x","status":{"phase":"online"}}`)
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":999999,"page":1,"pageSize":200,"items":[%s]}}`,
			strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("超过分页上限应返回错误，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("超过分页上限时不应返回（不完整的）代理列表")
	}
	if !strings.Contains(err.Error(), "分页上限") {
		t.Fatalf("错误信息应说明是分页上限，实际: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 50 {
		t.Fatalf("请求了 %d 页，期望取满 50 页后再报错", requests)
	}
}
