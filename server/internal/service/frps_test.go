package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

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

func frpsOK(data string) string {
	return `{"code":200,"msg":"success","data":` + data + `}`
}

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
	if !IsProxyOnline(proxies[0].Status.Phase) {
		t.Errorf("phase=%q 应判为在线", proxies[0].Status.Phase)
	}
	if !authOK {
		t.Error("没有带上 frps 管理接口的 basic auth")
	}
}

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

func TestListProxiesRejectsMalformedResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"非成功码（401）", `{"code":401,"msg":"unauthorized","data":null}`},
		{"非成功码但带 data", `{"code":1001,"msg":"invalid token","data":{"total":0,"items":[]}}`},
		{"缺 code 但有合法 data", `{"msg":"success","data":{"total":0,"items":[]}}`},
		{"code 为 null", `{"code":null,"data":{"total":0,"items":[]}}`},
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

func TestListProxiesNonOKStatusIsError(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"msg":"unauthorized"}`))
	})
	if _, err := c.ListProxies(context.Background()); err == nil {
		t.Fatal("非 200 状态码应返回错误")
	}
}

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
	if len(pages) != 3 {
		t.Fatalf("请求了 %d 页，期望 3 次（2 页 + 1 次复检），实际序列 %v", len(pages), pages)
	}
	if pages[0] != "1" || pages[1] != "2" || pages[2] != "1" {
		t.Fatalf("请求顺序 = %v，期望 [1 2 1]（最后一页之后复检第 1 页）", pages)
	}
	if proxies[200].Name != "lt_u1.last" {
		t.Fatalf("最后一条 = %q，期望 lt_u1.last", proxies[200].Name)
	}
}

func TestListProxiesRejectsShortPageWithRemainingTotal(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		items := make([]string, 0, 100)
		for i := 0; i < 100; i++ {
			items = append(items, fmt.Sprintf(`{"name":"lt_u1.x%d","status":{"phase":"online"}}`, i))
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

func TestListProxiesRejectsMissingTotalWithEmptyItems(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","data":{"page":1,"pageSize":200,"items":[]}}`))
	})
	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatal("缺少 total 时空列表不能当成「没有代理」，应报错")
	}
	if proxies != nil {
		t.Fatal("读不懂的响应不应返回代理列表")
	}
	if !strings.Contains(err.Error(), "total") {
		t.Fatalf("错误信息应指出缺少 total，实际: %v", err)
	}
}

func TestListProxiesRejectsMissingTotalWithShortPage(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","data":{"page":1,"pageSize":200,"items":[{"name":"lt_u1.mc","status":{"phase":"online"}}]}}`))
	})
	if _, err := c.ListProxies(context.Background()); err == nil {
		t.Fatal("total 缺失且页面非满时应报错")
	}
}

func TestListProxiesRejectsOversizedTotalReport(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()

		items := make([]string, 0, 200)
		for i := 0; i < 200; i++ {
			items = append(items, fmt.Sprintf(`{"name":"lt_u1.x%d","status":{"phase":"online"}}`, i))
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":999999,"page":1,"pageSize":200,"items":[%s]}}`,
			strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("total 超出采集上限应返回错误，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("超限时不应返回（不完整的）代理列表")
	}
	if !strings.Contains(err.Error(), "采集上限") {
		t.Fatalf("错误信息应说明是采集上限，实际: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("请求了 %d 页，期望第一页看清 total 后立刻放弃", requests)
	}
}

func TestListProxiesSupportsManyPages(t *testing.T) {
	const total = 12000

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := (page - 1) * frpsPageSize
		end := start + frpsPageSize
		if end > total {
			end = total
		}
		items := make([]string, 0, end-start)
		for i := start; i < end; i++ {
			items = append(items, fmt.Sprintf(`{"name":"lt_u1.t%d","status":{"phase":"online"}}`, i))
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":%d,"page":%d,"pageSize":%d,"items":[%s]}}`,
			total, page, frpsPageSize, strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("分页抓取失败: %v", err)
	}
	if len(proxies) != total {
		t.Fatalf("代理数 = %d，期望 %d", len(proxies), total)
	}
}

func TestListProxiesRejectsDuplicateNames(t *testing.T) {
	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		name := "lt_u1.mc"
		if page == "2" {
			name = "lt_u1.nas"
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":3,"page":%s,"pageSize":200,"items":[`+
			`{"name":"%s","status":{"phase":"online"}},{"name":"lt_u1.mc","status":{"phase":"online"}}]}}`, page, name)
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("重复代理应报错，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("结果不可信时不应返回代理列表")
	}
	if !strings.Contains(err.Error(), "重复") {
		t.Fatalf("错误信息应指出重复，实际: %v", err)
	}
}

func TestListProxiesDetectsTotalChangeMidPagination(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		round := (requests - 1) / 2
		mu.Unlock()

		page := r.URL.Query().Get("page")
		total := 201
		if page == "2" {
			total = 202
		}
		items := make([]string, 0, frpsPageSize)
		count := frpsPageSize
		if page == "2" {
			count = 1
		}
		for i := 0; i < count; i++ {
			items = append(items, fmt.Sprintf(`{"name":"lt_u1.r%d.p%s.%d","status":{"phase":"online"}}`,
				round, page, i))
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":%d,"page":%s,"pageSize":%d,"items":[%s]}}`,
			total, page, frpsPageSize, strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("分页期间 total 变化应报错，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("结果不稳定时不应返回代理列表")
	}
	if !strings.Contains(err.Error(), "分页期间") {
		t.Fatalf("错误信息应说明分页期间发生变化，实际: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests < frpsListAttempts*2 {
		t.Fatalf("请求了 %d 次，期望重取一次（两轮 × 两页）", requests)
	}
}

func TestListProxiesDetectsCollectionChangeWithSameTotal(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	const total = 2 * frpsPageSize

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()

		page := r.URL.Query().Get("page")
		items := make([]string, 0, frpsPageSize)
		switch page {
		case "1":
			base := 0
			if (n-1)%3 == 2 {
				base = 1
			}
			for i := 0; i < frpsPageSize; i++ {
				items = append(items, fmt.Sprintf(`{"name":"lt_u1.a%d","status":{"phase":"online"}}`, base+i))
			}
		default:
			for i := 0; i < frpsPageSize; i++ {
				items = append(items, fmt.Sprintf(`{"name":"lt_u1.b%d","status":{"phase":"online"}}`, i))
			}
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":%d,"page":%s,"pageSize":%d,"items":[%s]}}`,
			total, page, frpsPageSize, strings.Join(items, ","))
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("total 不变但集合变化应报错，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("结果不稳定时不应返回代理列表：错位的条目会让人被判离线、让新代理被多计流量")
	}
	if !strings.Contains(err.Error(), "集合变了") {
		t.Fatalf("错误信息应说明集合发生变化，实际: %v", err)
	}
}

func TestListProxiesRechecksFirstPageOnlyWhenPaginated(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":%d,"items":[{"name":"lt_u1.only","status":{"phase":"online"}}]}}`,
			frpsPageSize)
	})

	proxies, err := c.ListProxies(context.Background())
	if err != nil {
		t.Fatalf("单页列表不该报错: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("期望 1 条，实际 %d 条", len(proxies))
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("单页只应请求 1 次（不做复检），实际 %d 次", requests)
	}
}

func TestCloseUserProxiesStopsWhenStatusChanges(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 7
	startedAt := time.Now().Add(-time.Minute).Unix()
	var (
		mu     sync.Mutex
		closed []string
		bumped bool
	)
	svc.Frps = newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(frpsOK(fmt.Sprintf(
				`{"total":2,"page":1,"pageSize":200,"items":[`+
					`{"name":"lt_u7.mc","status":{"phase":"online","lastStartAt":%d}},`+
					`{"name":"lt_u7.nas","status":{"phase":"online","lastStartAt":%d}}]}`,
				startedAt, startedAt))))
		case r.Method == http.MethodDelete:
			mu.Lock()
			closed = append(closed, r.URL.Query().Get("name"))
			if !bumped {
				bumped = true
				svc.bumpUserStatusGen(userID)
			}
			mu.Unlock()
			_, _ = w.Write([]byte(frpsOK("null")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	gen := svc.bumpUserStatusGen(userID)
	svc.CloseUserProxies(context.Background(), userID, gen, time.Now())

	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 1 {
		t.Fatalf("状态变更后不应继续关闭剩余代理，实际关闭了 %v", closed)
	}
}

func TestCloseUserProxiesHoldsUserLockWhileClosing(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 9
	startedAt := time.Now().Add(-time.Minute).Unix()
	var lockHeld int32 = 1
	svc.Frps = newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(frpsOK(fmt.Sprintf(
				`{"total":1,"page":1,"pageSize":200,"items":[`+
					`{"name":"lt_u9.mc","status":{"phase":"online","lastStartAt":%d}}]}`,
				startedAt))))
		case r.Method == http.MethodDelete:
			lock := svc.userLock(userID)
			if lock.TryLock() {
				lock.Unlock()
				atomic.StoreInt32(&lockHeld, 0)
			}
			_, _ = w.Write([]byte(frpsOK("null")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	gen := svc.bumpUserStatusGen(userID)
	svc.CloseUserProxies(context.Background(), userID, gen, time.Now())

	if atomic.LoadInt32(&lockHeld) == 0 {
		t.Fatal("关闭代理时没有持有用户锁：复查与关闭之间仍可能插入一次重新启用")
	}
}

func TestCloseUserProxiesSkipsProxiesStartedAfterDisable(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 11
	now := time.Now().Unix()
	var (
		mu     sync.Mutex
		closed []string
	)
	svc.Frps = newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(frpsOK(fmt.Sprintf(
				`{"total":2,"page":1,"pageSize":200,"items":[`+
					`{"name":"lt_u11.old","status":{"phase":"online","lastStartAt":%d}},`+
					`{"name":"lt_u11.new","status":{"phase":"online","lastStartAt":%d}}]}`,
				now-60, now+10))))
		case http.MethodDelete:
			mu.Lock()
			closed = append(closed, r.URL.Query().Get("name"))
			mu.Unlock()
			_, _ = w.Write([]byte(frpsOK("null")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	gen := svc.bumpUserStatusGen(userID)
	svc.CloseUserProxies(context.Background(), userID, gen, time.Now())

	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 1 || closed[0] != "lt_u11.old" {
		t.Fatalf("只应关闭禁用前就存在的代理，实际关闭了 %v", closed)
	}
}
