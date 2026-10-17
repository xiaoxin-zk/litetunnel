package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 这一组守的是「隧道清单必须取全且自洽」：
// 只取第一页、或拿分页期间已经变化的清单去对账，都会把漏掉的隧道
// 当成「服务端已删除」——停掉本机进程并删掉本地配置。

// pagedPanel 起一个按 before_id 游标分页的假面板，共 n 条隧道。
// inconsistent 为 true 时，第一页报告的总数比实际能取到的多，
// 模拟「分页期间隧道被删除」。
func pagedPanel(t *testing.T, n int, inconsistent *atomic.Bool) *httptest.Server {
	t.Helper()
	var firstPage atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beforeID, _ := strconv.Atoi(r.URL.Query().Get("before_id"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = n
		}
		// 模拟后的 id 从 1 到 n，按倒序返回 id < beforeID 的前 limit 条。
		total := n
		if inconsistent != nil && inconsistent.Load() {
			total = n + 3 // 报告的总数比实际可取到的多
			// 只让第一页「不一致」：第一页之后其余页正常（少几条）。
			if firstPage.Add(1) > 1 {
				total = n
			}
		}
		ids := make([]int, 0, n)
		for id := n; id >= 1; id-- {
			if beforeID > 0 && id >= beforeID {
				continue
			}
			if len(ids) >= limit {
				break
			}
			ids = append(ids, id)
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"code":0,"message":"ok","data":{"username":"u","tunnel_total":%d,"tunnels":[`, total)
		for i, id := range ids {
			if i > 0 {
				body += ","
			}
			body += fmt.Sprintf(`{"id":%d,"name":"t%d","type":"tcp","status":"active"}`, id, id)
		}
		body += `]}}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchClientInfoWalksAllPages 覆盖「沿游标跨页取全」。
func TestFetchClientInfoWalksAllPages(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	srv := pagedPanel(t, 5, nil)
	a := newSyncTestApp(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err != nil {
		t.Fatalf("分页拉取失败: %v", err)
	}
	if len(data.Tunnels) != 5 {
		t.Fatalf("应取全 5 条隧道，实际 %d 条", len(data.Tunnels))
	}
	seen := map[uint]bool{}
	for _, tun := range data.Tunnels {
		if seen[tun.ID] {
			t.Fatalf("隧道 %d 重复出现", tun.ID)
		}
		seen[tun.ID] = true
	}
}

// TestFetchClientInfoToleratesOldServer 覆盖「老服务端不分页」。
//
// 老服务端忽略分页参数，也不返回 tunnel_total：客户端应把这一页
// 当成全部，行为与升级前一致，不能因为 total=0 就反复翻页。
func TestFetchClientInfoToleratesOldServer(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"code":0,"message":"ok","data":{"username":"u","tunnels":[` +
				`{"id":1,"name":"a","type":"tcp","status":"active"},` +
				`{"id":2,"name":"b","type":"tcp","status":"active"},` +
				`{"id":3,"name":"c","type":"tcp","status":"active"}]}}`))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if len(data.Tunnels) != 3 {
		t.Fatalf("老服务端应一次返回全部 3 条，实际 %d 条", len(data.Tunnels))
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("老服务端不应触发翻页，实际请求 %d 次", got)
	}
}

// TestFetchClientInfoRetriesOnChangedList 覆盖「清单变化时重取而不是将就」。
//
// 第一轮分页期间隧道被删：取到的条数少于服务端报告的总数。
// 此时必须整轮重取（第二轮自洽），而不是把不完整清单交给对账。
func TestFetchClientInfoRetriesOnChangedList(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	var inconsistent atomic.Bool
	inconsistent.Store(true)
	srv := pagedPanel(t, 4, &inconsistent)
	a := newSyncTestApp(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err != nil {
		t.Fatalf("重取后应成功: %v", err)
	}
	if len(data.Tunnels) != 4 {
		t.Fatalf("重取后应拿到自洽的 4 条，实际 %d 条", len(data.Tunnels))
	}
}

// TestFetchClientInfoFailsWhenListKeepsChanging 覆盖「持续不一致必须报错」。
//
// 两轮都对不上时不能「返回已收集的部分」：那会把漏掉的隧道当成
// 已删除，客户端会停掉它们的进程并删掉本地配置。宁可本轮同步失败，
// 由下一轮自动同步再来。
func TestFetchClientInfoFailsWhenListKeepsChanging(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 永远报告 5 条，但只给 2 条，且后续页为空。
		body := `{"code":0,"message":"ok","data":{"username":"u","tunnel_total":5,"tunnels":[`
		if r.URL.Query().Get("before_id") == "" {
			body += `{"id":5,"name":"a","type":"tcp","status":"active"},` +
				`{"id":4,"name":"b","type":"tcp","status":"active"}`
		}
		body += `]}}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err == nil {
		t.Fatal("清单持续不一致时必须报错，不能返回不完整结果")
	}
	if !strings.Contains(err.Error(), "取到 2 条") {
		t.Fatalf("错误应说明条数不符，实际 %v", err)
	}
}
