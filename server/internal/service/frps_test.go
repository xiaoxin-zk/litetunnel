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
			// 名字必须互不相同：重复项属于另一类「结果不可信」，
			// 本用例要验证的是短页判定，别让重复检测抢先命中。
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

// TestListProxiesRejectsMissingTotalWithEmptyItems 覆盖「缺 total + 空 items」。
//
// total 解成普通 int 时缺字段会默认 0，配上空 items 就成了「frps 明确告诉我们
// 没有任何代理」——采集器据此把所有隧道判成离线，而真实情况是我们没读懂响应。
// 必须与「total: 0 且 items 为空」区分开。
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

// TestListProxiesRejectsOversizedTotalReport 覆盖「对端报了荒谬的 total」。
//
// 上限本身按 total 推算（默认 500 页 × 200 条 = 10 万），超过就提前报错，
// 不必真的翻满 500 页。旧实现是写死 50 页：代理数一过一万，采集就永久失败，
// 而表现只是「在线状态停在旧值」。
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

// TestListProxiesSupportsManyPages 覆盖「代理数超过旧的一万条上限」。
//
// 页数必须按 total 推算：12000 条（60 页）应当能完整取回。
// 旧实现取满 50 页就报错，规模一过线采集永久失效。
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

// TestListProxiesRejectsDuplicateNames 覆盖「同一代理在两页里各出现一次」。
//
// 重复项不能「尽力去重」了事：runtime 是按条累加流量的，同一条代理出现两次
// 就会把同一段流量计两遍。整轮结果一律作废（重取一次后仍重复就报错），
// 调用方保住上一轮的在线状态与采样基线。
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

// TestListProxiesDetectsTotalChangeMidPagination 覆盖「翻页期间 total 变了」。
//
// 说明这两页看到的不是同一份集合：可能漏、也可能重。整轮作废重取，
// 仍然不稳定就报错（宁可这一轮不采，也不能拿它去重建在线状态）。
func TestListProxiesDetectsTotalChangeMidPagination(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		round := (requests - 1) / 2 // 每轮两页
		mu.Unlock()

		page := r.URL.Query().Get("page")
		// 第一页说 201 条，第二页却说 202 条：这两页看到的不是同一份集合。
		total := 201
		if page == "2" {
			total = 202
		}
		// 名字按轮次+页次区分，避免「重复」抢先命中。
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

// TestListProxiesDetectsCollectionChangeWithSameTotal 覆盖「删一条 + 加一条、
// total 不变」这种最隐蔽的分页错位。
//
// 分页接口没有稳定快照：frps 按 (type, name) 排序后切片，翻页期间有人删了一条
// 又加了一条，total 自始至终不变，但删除点之后的页整体错位一格——被跳过的那条
// 旧代理不在结果里（随后被判离线），新加的那条被多读一次（随后被判在线）。
// 条数校验、total 校验、重复校验**全部发现不了**，只有翻页结束后复检第 1 页
// 才能看出来（见 recheckFirstPage）。
//
// 构造：第 1 轮第 1 页是 A 组、第 2 页是 B 组；第 2 轮（复检）第 1 页换成 A'
// 组（条数完全相同、只有内容变了），于是复检必须报不稳定。
func TestListProxiesDetectsCollectionChangeWithSameTotal(t *testing.T) {
	var mu sync.Mutex
	requests := 0

	// total 固定 2：一页放 1 条，共两页，保证一定翻页（单页不走复检）。
	const total = 2

	c := newTestFrps(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		n := requests
		mu.Unlock()

		page := r.URL.Query().Get("page")
		// 第 1 页在第 3 次请求（= 第 2 轮复检）时换名字：
		// 条数没变、total 没变，只有集合变了。
		var name string
		switch {
		case page == "1" && n <= 2:
			name = "lt_u1.a"
		case page == "1":
			name = "lt_u1.a-new" // 一删一增之后的名单
		default:
			name = "lt_u1.b"
		}
		fmt.Fprintf(w, `{"code":200,"msg":"success","data":{"total":%d,"page":%s,"pageSize":1,"items":[{"name":%q,"status":{"phase":"online"}}]}}`,
			total, page, name)
	})

	proxies, err := c.ListProxies(context.Background())
	if err == nil {
		t.Fatalf("total 不变但集合变化应报错，实际拿到 %d 条且无错误", len(proxies))
	}
	if proxies != nil {
		t.Fatal("结果不稳定时不应返回代理列表：错位的条目会让人被判离线、让新代理被多计流量")
	}
	if !strings.Contains(err.Error(), "分页期间") {
		t.Fatalf("错误信息应说明分页期间发生变化，实际: %v", err)
	}
}

// TestListProxiesRechecksFirstPageOnlyWhenPaginated 覆盖「单页不做复检」。
//
// 单页时 total 与 items 出自 frps 的同一次请求（同一个切片算出来的），本身就是
// 一致快照，再复检一次只是白花一个往返。健康检查与采集是高频路径，这个开销必须
// 省掉。
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

// TestCloseUserProxiesStopsWhenStatusChanges 覆盖「断流途中账号被重新启用」。
//
// 禁用流程在放掉用户锁之后才断流（断流可能十几秒）。这段时间里管理员可以把
// 账号重新启用，客户端随即重连并建立新代理——继续按几秒前那份列表往下关，
// 关的就是刚放行的人。代次一变，本次断流必须停手。
//
// fixture 必须给每条代理一个可判定的实例身份（clientID 或 lastStartAt）：
// 两者都缺失时实现会按「身份不可判定」跳过关闭（见问题 9），这样构造的用例
// 连一条代理都不会关，测的就不再是代次守卫了。真实 frps 的管理接口总会带上
// lastStartAt，所以这里用 lastStartAt 是更贴近现实的构造。
func TestCloseUserProxiesStopsWhenStatusChanges(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 7
	// 代理的启动时间必须在两次列表调用之间保持不变：实现会用它对齐「同一个
	// 代理实例」，若每次列表都重新取 time.Now()，跨过一个整秒边界就会对不上，
	// 用例随机失败。
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
			// 第一次关闭生效期间，管理端把账号重新启用：代次推进。
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

// TestCloseUserProxiesHoldsUserLockWhileClosing 覆盖「复查之后、请求之前」的窄窗口。
//
// 只复查代次是不够的：检查通过到请求真正发出之间，管理端仍可能完成一次
// 重新启用，那条刚建立的代理照样会被关掉。所以复查与关闭必须在同一把
// 用户锁内——关的时候别人改不了状态。
//
// fixture 带 lastStartAt：双空身份会被判成「身份不可判定」而跳过关闭，
// 那样 DELETE 根本不会发生，这条用例就测不到锁了。
func TestCloseUserProxiesHoldsUserLockWhileClosing(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 9
	// 同上：启动时间在整个用例内固定，否则列表快照与复查快照对不上。
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

// TestCloseUserProxiesSkipsProxiesStartedAfterDisable 覆盖跨实例的最后一跳竞态。
//
// 锁与代次都只能覆盖本实例：另一台实例上的启用可以正好插在查库之后、
// 关闭请求到达 frps 之前。frps 记录的 lastStartAt 是这种情形下唯一可信的
// 判据——重新注册过的代理一定晚于禁用时刻启动，关它等于把刚放行的人
// 又踢下线。
func TestCloseUserProxiesSkipsProxiesStartedAfterDisable(t *testing.T) {
	svc := newTestServices(t, nil)
	t.Cleanup(svc.Close)

	const userID = 11
	// 两条代理的启动时间在整个用例内固定（而不是每次列表都重取 time.Now()）：
	// 实现会用 lastStartAt 对齐「还是不是同一个代理实例」，跨过一个整秒边界
	// 就会对不上而跳过关闭，用例随机失败。取值本身仍保持原语义——
	// old 早于禁用时刻，new 晚于禁用时刻。
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
