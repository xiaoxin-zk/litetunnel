package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 这一组守的是「清单快照的完整性与新鲜度」：
//   - 服务端报告有隧道却返回空页时不能 panic；
//   - 拉取早、应用晚的过期清单不得参与对账（会停掉新清单里的隧道）。

// TestFetchClientInfoEmptyFirstPageIsError 覆盖「总数 > 0 但首页为空」。
//
// 服务端先查总数、再查列表，两次查询之间隧道可能被删空。此时若直接进
// 分页循环，对空切片取末元素会 panic——自动同步协程里的 panic 会直接
// 终止客户端。这里要求按「清单已变化」报错，绝不能 panic。
func TestFetchClientInfoEmptyFirstPageIsError(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"code":0,"message":"ok","data":{"username":"u","tunnel_total":3,"tunnels":[]}}`))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("空首页不得进入游标计算（panic: %v）", r)
		}
	}()
	_, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err == nil {
		t.Fatal("总数与列表矛盾时必须报错，不能返回空清单当成功")
	}
	if !strings.Contains(err.Error(), "本页为空") {
		t.Fatalf("错误应说明首页为空，实际 %v", err)
	}
}

// TestStaleSnapshotNotApplied 覆盖「过期快照整份丢弃」。
//
// 接入流程先拉到清单、后台同步后拉先应用：接入随后若照旧应用旧清单，
// 会把新清单里的隧道当成「服务端已删除」而停掉进程。序号更小的快照
// 必须被拒绝，且不产生任何起停副作用。
func TestStaleSnapshotNotApplied(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	fresh := &clientInfoData{Username: "u", Tunnels: []TunnelVO{}}
	stale := &clientInfoData{Username: "u", Tunnels: []TunnelVO{
		{ID: 9, Name: "old", Type: "tcp", Status: "active"},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := a.applySyncData(ctx, fresh, 2); err != nil {
		t.Fatalf("应用新快照失败: %v", err)
	}
	changed, err := a.applySyncData(ctx, stale, 1)
	if err != nil {
		t.Fatalf("过期快照应被静默丢弃: %v", err)
	}
	if changed {
		t.Fatal("过期快照不得被当成变更")
	}
	if len(a.tunnels) != 0 {
		t.Fatalf("过期清单不得覆盖当前清单，实际 %d 条", len(a.tunnels))
	}
	if len(a.retries) != 0 || len(a.tunnelErrs) != 0 {
		t.Fatal("过期清单不得触发任何进程起停")
	}
	if a.appliedSyncSeq != 2 {
		t.Fatalf("已应用序号应保持为 2，实际 %d", a.appliedSyncSeq)
	}
}
