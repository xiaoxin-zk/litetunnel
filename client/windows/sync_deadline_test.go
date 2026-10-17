package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// TestSyncRoundResumesAfterTimeout 覆盖「清单尾部隧道永远轮不到配置」。
//
// 清单按 id 倒序返回、配置并发 6 条、整轮 45 秒截止：若每轮都从清单开头
// 开始，前面几条一旦持续卡到超时，后面的隧道就永远排不上——新建的隧道
// 一直「连接中」、改了配置的一直跑旧配置，而且重启客户端也没用（位次没变）。
// 现在每轮记下派发到哪儿，下一轮从那里环形开始，被砍掉的尾部排到最前。
func TestSyncRoundResumesAfterTimeout(t *testing.T) {
	oldTimeout := syncRoundTimeout
	syncRoundTimeout = 100 * time.Millisecond
	t.Cleanup(func() { syncRoundTimeout = oldTimeout })

	var mu sync.Mutex
	requested := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			mu.Lock()
			requested[r.URL.Query().Get("tunnel_id")] = true
			mu.Unlock()
			<-r.Context().Done() // 挂到本轮超时为止
			return
		}
		// /client/info：12 条启用中的隧道，与真实服务端一样按 id 倒序。
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[`)
		for i := 12; i >= 1; i-- {
			if i != 12 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"id":` + itoa(i) + `,"name":"t","type":"tcp","status":"active"}`)
		}
		sb.WriteString(`]}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)

	if _, err := a.syncLocked(); err == nil {
		t.Fatal("配置接口全部挂住时，本轮同步应报超时")
	}
	if a.syncStart == 0 {
		t.Fatal("超时后必须推进续传位置，否则下一轮还是从同一批隧道开始")
	}
	first := make(map[string]bool, len(requested))
	mu.Lock()
	for id := range requested {
		first[id] = true
	}
	mu.Unlock()

	if _, err := a.syncLocked(); err == nil {
		t.Fatal("第二轮同样会超时")
	}

	mu.Lock()
	fresh := 0
	for id := range requested {
		if !first[id] {
			fresh++
		}
	}
	mu.Unlock()
	if fresh == 0 {
		t.Fatal("第二轮必须处理到第一轮没轮上的隧道，否则尾部隧道永远拿不到配置")
	}
}

// TestSyncCursorFollowsManifestPosition 覆盖「缓存命中把游标推过头」。
//
// 续传位置必须按**原清单里的位置**推进,而不是「派发数 + 命中缓存数」:
// 命中缓存是散布在清单各处的(哪条没变跳过哪条),按个数相加会把游标推到
// 清单里更靠后的位置,中间那些还没轮到请求的隧道被整段跳过。极端情况下
// (前几批一直超时)游标会在两个位置之间来回,尾部几条永远进不了请求队列,
// 一直跑着旧配置或压根没启动。
func TestSyncCursorFollowsManifestPosition(t *testing.T) {
	oldTimeout := syncRoundTimeout
	syncRoundTimeout = 100 * time.Millisecond
	t.Cleanup(func() { syncRoundTimeout = oldTimeout })

	const total = 40

	var mu sync.Mutex
	requested := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			mu.Lock()
			requested[r.URL.Query().Get("tunnel_id")] = true
			mu.Unlock()
			<-r.Context().Done() // 挂到本轮超时
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[`)
		for i := 0; i < total; i++ {
			if i != 0 {
				sb.WriteString(",")
			}
			id := i + 1
			// 奇数位隧道带摘要(测试里当作「已缓存」),偶数位不带(需要拉取)。
			rev := ""
			if i%2 == 1 {
				rev = `,"config_rev":"rev-` + itoa(i) + `"`
			}
			sb.WriteString(`{"id":` + itoa(id) + `,"name":"t","type":"tcp","status":"active"` + rev + `}`)
		}
		sb.WriteString(`]}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	// 构造「这些隧道上一轮已经成功应用过」的状态:摘要与本地记账一致,
	// 于是这一轮它们不需要再拉。
	for i := 0; i < total; i++ {
		if i%2 != 1 {
			continue
		}
		id := uint(i + 1)
		a.applied[id] = "serverAddr = \"127.0.0.1\"\n"
		a.cfgRev[id] = "rev-" + itoa(i)
	}

	_, _ = a.applySync()

	// 本轮实际请求到的隧道在清单里的最大位次,就是游标该停的地方。
	maxIdx := -1
	mu.Lock()
	var bad []string
	for i := 0; i < total; i++ {
		if !requested[itoa(i+1)] {
			continue
		}
		if i%2 != 0 {
			bad = append(bad, itoa(i+1)) // 带了摘要,不该被请求
		}
		if i > maxIdx {
			maxIdx = i
		}
	}
	mu.Unlock()

	if maxIdx < 0 {
		t.Fatal("本轮应至少派发出一条配置请求")
	}
	if len(bad) > 0 {
		t.Fatalf("带摘要(无需拉取)的隧道不该被请求:%v", bad)
	}
	want := (maxIdx + 1) % total
	if a.syncStart != want {
		t.Fatalf("续传位置 = %d,期望 %d:必须跟着最后一个被派发的隧道走，"+
			"按「派发数 + 命中缓存数」推进会整段跳过未被请求的隧道", a.syncStart, want)
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

	results, _ := a.streamTunnelConfigs(ctx, srv.URL, "k", tunnels)
	count := 0
	for range results {
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
