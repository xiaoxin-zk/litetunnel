package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// 这一组守的是「隧道清单必须取全」：只取第一页就把不完整清单当全量，
// 对账会把后面几页的隧道当成「服务端已删除」，停掉本机进程并删掉配置。

// pagedPanel 起一个支持 offset/limit 分页的假面板，共 n 条隧道。
func pagedPanel(t *testing.T, n int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = n
		}
		if offset > n {
			offset = n
		}
		end := offset + limit
		if end > n {
			end = n
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"code":0,"message":"ok","data":{"username":"u","tunnel_total":%d,"tunnels":[`, n)
		for i := offset; i < end; i++ {
			if i > offset {
				body += ","
			}
			body += fmt.Sprintf(`{"id":%d,"name":"t%d","type":"tcp","status":"active"}`, i+1, i+1)
		}
		body += `]}}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchClientInfoWalksAllPages 覆盖「跨页取全」。
func TestFetchClientInfoWalksAllPages(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	srv := pagedPanel(t, 5)
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
// 老服务端忽略 offset/limit，也不返回 tunnel_total：客户端应把这一页
// 当成全部，行为与升级前一致，不能因为 total=0 就反复翻页。
func TestFetchClientInfoToleratesOldServer(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
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
	if requests != 1 {
		t.Fatalf("老服务端不应触发翻页，实际请求 %d 次", requests)
	}
}
