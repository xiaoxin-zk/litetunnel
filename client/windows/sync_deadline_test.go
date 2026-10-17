package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 这一组守的是「整轮同步限时」：手动操作（启动/停止/退出）要等同步
// 释放 syncMu，配置拉取阶段必须有限时，不能被「隧道数 × 单次超时」
// 拖到无界。

// TestSyncRoundTimeoutCutsOffSlowFetch 覆盖「拉取超时后本轮立即收尾」。
//
// 服务端的配置接口一直挂着不响应：旧实现里整轮耗时约为
// 「隧道数 × 单次超时 / 并发数」，隧道一多手动操作就被挡几分钟。
// 现在整轮有截止时间，超时后立即返回错误（下一轮自动补齐剩余隧道）。
func TestSyncRoundTimeoutCutsOffSlowFetch(t *testing.T) {
	// 把截止时间压短，避免测试本身等太久。
	oldTimeout := syncRoundTimeout
	syncRoundTimeout = 100 * time.Millisecond
	t.Cleanup(func() { syncRoundTimeout = oldTimeout })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			// 挂住直到测试结束：模拟一个不通的配置接口。
			<-release
			return
		}
		// /client/info：返回 12 条启用中的隧道。
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[`)
		for i := 0; i < 12; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"id":`)
			sb.WriteString(itoa(i + 1))
			sb.WriteString(`,"name":"t","type":"tcp","status":"active"}`)
		}
		sb.WriteString(`]}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	a := newSyncTestApp(t, srv)

	start := time.Now()
	_, err := a.syncLocked()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("配置接口全部挂住时，本轮同步应报错而不是静默成功")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("错误应说明是本轮超时，实际 %v", err)
	}
	// 单次请求超时 5 秒；限时生效的话远等不到它。
	if elapsed > 3*time.Second {
		t.Fatalf("整轮应在截止时间内返回，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
	// fetch 失败不该推进进程退避（failSync 而非 failStart）。
	if st := a.retries[1]; st != nil {
		t.Fatalf("拉取超时不是启动失败，不应推进退避: %+v", st)
	}
}

// TestStreamTunnelConfigsStopsOnCanceledContext 覆盖「截止后不再派发」。
//
// 取消的 context 下，worker 不应再发起任何请求，结果通道正常关闭，
// 调用方的 range 不会卡住。
func TestStreamTunnelConfigsStopsOnCanceledContext(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n"))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	tunnels := make([]TunnelVO, 30)
	for i := range tunnels {
		tunnels[i] = TunnelVO{ID: uint(i + 1), Name: "t", Status: tunnelStatusActive}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 一开始就取消

	count := 0
	for range a.streamTunnelConfigs(ctx, srv.URL, "k", tunnels) {
		count++
	}
	if count != 0 {
		t.Fatalf("取消后不应流出任何结果，实际 %d 条", count)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
