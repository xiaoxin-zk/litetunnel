package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSyncRoundTimeoutCutsOffSlowFetch(t *testing.T) {
	oldTimeout := syncRoundTimeout
	syncRoundTimeout = 100 * time.Millisecond
	t.Cleanup(func() { syncRoundTimeout = oldTimeout })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			<-release
			return
		}
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
	if elapsed > 3*time.Second {
		t.Fatalf("整轮应在截止时间内返回，实际耗时 %s", elapsed.Round(time.Millisecond))
	}
	if st := a.retries[1]; st != nil {
		t.Fatalf("拉取超时不是启动失败，不应推进退避: %+v", st)
	}
}

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
			<-r.Context().Done()
			return
		}
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
			<-r.Context().Done()
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
	for i := 0; i < total; i++ {
		if i%2 != 1 {
			continue
		}
		id := uint(i + 1)
		a.applied[id] = "serverAddr = \"127.0.0.1\"\n"
		a.cfgRev[id] = "rev-" + itoa(i)
	}

	_, _ = a.applySync()

	maxIdx := -1
	mu.Lock()
	var bad []string
	for i := 0; i < total; i++ {
		if !requested[itoa(i+1)] {
			continue
		}
		if i%2 != 0 {
			bad = append(bad, itoa(i+1))
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
	cancel()

	results, _ := a.streamTunnelConfigs(ctx, srv.URL, "k", tunnels)
	count := 0
	for range results {
		count++
	}
	if count != 0 {
		t.Fatalf("取消后不应流出任何结果，实际 %d 条", count)
	}
}

func TestWriteAndStartSkipsWorkAfterDeadline(t *testing.T) {
	dir := withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := 0; i < 3; i++ {
		a.noteStartFailure(1, "mc", "启动失败")
	}

	tun := TunnelVO{
		ID: 1, Name: "mc", Type: "tcp", Status: tunnelStatusActive,
		LocalIP: "127.0.0.1", LocalPort: 25565,
	}
	err := a.writeAndStart(ctx, tun, "serverAddr = \"127.0.0.1\"\n")

	if !errors.Is(err, errSyncDeadline) {
		t.Fatalf("超时后应返回 errSyncDeadline（调用方据此不记失败），实际 %v", err)
	}
	if a.mgr.Running(1) {
		t.Fatal("超时后不得拉起进程：界面会同时显示「同步超时」和一条已连上的隧道")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "tunnels", "1", "frpc.toml")); statErr == nil {
		t.Fatal("超时后不得落盘配置：那一份配置既没被应用也没被记账")
	}
	if got := a.retries[1].attempts; got != 3 {
		t.Fatalf("退避计数 = %d，期望仍是 3：超时路径不该改动退避状态", got)
	}
}

func TestApplySyncDeadlineDoesNotCountTunnelAsFailed(t *testing.T) {
	oldTimeout := syncRoundTimeout
	syncRoundTimeout = 100 * time.Millisecond
	t.Cleanup(func() { syncRoundTimeout = oldTimeout })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			<-release
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var sb strings.Builder
		sb.WriteString(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[`)
		for i := 0; i < 8; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"id":` + itoa(i+1) + `,"name":"t` + itoa(i+1) + `","type":"tcp","status":"active"}`)
		}
		sb.WriteString(`]}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	a := newSyncTestApp(t, srv)
	_, err := a.syncLocked()
	if err == nil {
		t.Fatal("配置接口全部挂住时应收尾报错")
	}
	if strings.Contains(err.Error(), "隧道同步失败") {
		t.Fatalf("超时跳过的隧道不是失败，不该计入失败条数：%v", err)
	}
	if strings.Contains(err.Error(), "另有") {
		t.Fatalf("超时路径不应追加失败明细：%v", err)
	}
	for id, st := range a.retries {
		if st != nil {
			t.Fatalf("隧道 %d 因超时被记了退避 %+v：下一轮会被白白推迟", id, st)
		}
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

func TestSyncCursorStopsAtFirstUnappliedTunnel(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	const (
		fast  = 5
		total = 12
	)

	var fastReplied atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/client/config") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[]}}`))
			return
		}
		id, _ := strconv.Atoi(r.URL.Query().Get("tunnel_id"))
		if id <= fast {
			w.Header().Set(configRevHeader, "rev-"+itoa(id))
			_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n"))
			fastReplied.Add(1)
			return
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)

	tunnels := make([]TunnelVO, total)
	for i := range tunnels {
		tunnels[i] = TunnelVO{
			ID: uint(i + 1), Name: "t" + itoa(i+1), Type: "tcp", Status: tunnelStatusActive,
			LocalIP: "127.0.0.1", LocalPort: 25565,
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= fast; i++ {
			for a.retryAllowed(uint(i)) {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, _ = a.applySyncData(ctx, &clientInfoData{Username: "u", Tunnels: tunnels}, 1)
	<-done

	if a.syncStart != fast {
		t.Fatalf("续传位置 = %d，期望 %d：游标必须停在第一条没落定的隧道上，"+
			"按派发数推进会越过它们，让它们整整一轮不再被处理", a.syncStart, fast)
	}
	for i := fast + 1; i <= total; i++ {
		if st, ok := a.retries[uint(i)]; ok && st != nil {
			t.Fatalf("隧道 %d 因截止时间未处理，却被记了退避 %+v", i, st)
		}
		if e, ok := a.tunnelErrs[uint(i)]; ok && e.msg != "" {
			t.Fatalf("隧道 %d 因截止时间未处理，却被记了失败原因 %q", i, e.msg)
		}
	}
}

func TestSyncRoundNextStart(t *testing.T) {
	const n = 6
	order := make([]TunnelVO, n)
	for i := range order {
		order[i] = TunnelVO{ID: uint(i + 1)}
	}
	allPos := []int{0, 1, 2, 3, 4, 5}

	cases := []struct {
		name    string
		rot     int
		settle  []int
		dispat  int
		pos     []int
		want    int
		comment string
	}{
		{
			name: "全部落定回到起点", rot: 0, settle: []int{0, 1, 2, 3, 4, 5},
			dispat: 6, pos: allPos, want: 0,
			comment: "整轮完成，顺序不变",
		},
		{
			name: "停在前缀之后", rot: 0, settle: []int{0, 1}, dispat: 6, pos: allPos, want: 2,
			comment: "第一条没落定的位置就是下一轮起点",
		},
		{
			name: "非连续落定仍停在第一个缺口", rot: 0, settle: []int{0, 1, 3, 4},
			dispat: 6, pos: allPos, want: 2,
			comment: "缺口之前都落定、之后有落定，也不能越过缺口",
		},
		{
			name: "环形左移后加回 rot", rot: 4, settle: []int{0, 1, 2}, dispat: 6, pos: allPos, want: 1,
			comment: "(4+3) % 6 = 1，不能漏掉 rot",
		},
		{
			name: "颗粒无收退回派发轮转", rot: 0, settle: nil, dispat: 3, pos: allPos, want: 3,
			comment: "整轮没落定：按派发进度轮转，避免尾部饿死",
		},
		{
			name: "颗粒无收且没派发", rot: 2, settle: nil, dispat: 0, pos: allPos, want: 2,
			comment: "什么都没发生，游标不动",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSyncRound(order, c.pos)
			for _, i := range c.settle {
				r.settle(order[i].ID)
			}
			r.setDispatched(c.dispat)
			if got := r.nextStart(c.rot, n); got != c.want {
				t.Fatalf("nextStart = %d，期望 %d（%s）", got, c.want, c.comment)
			}
		})
	}
}

type gateCtx struct {
	calls int
	errAt int
}

func (c *gateCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *gateCtx) Done() <-chan struct{}       { return nil }
func (c *gateCtx) Value(any) any               { return nil }
func (c *gateCtx) Err() error {
	c.calls++
	if c.calls >= c.errAt {
		return context.DeadlineExceeded
	}
	return nil
}

func TestWriteAndStartFinalGateLeavesNoState(t *testing.T) {
	withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	for i := 0; i < 3; i++ {
		a.noteStartFailure(1, "mc", "启动失败")
	}

	ctx := &gateCtx{errAt: 3}
	tun := TunnelVO{
		ID: 1, Name: "mc", Type: "tcp", Status: tunnelStatusActive,
		LocalIP: "127.0.0.1", LocalPort: 25565,
	}
	err := a.writeAndStart(ctx, tun, "serverAddr = \"127.0.0.1\"\n")

	if !errors.Is(err, errSyncDeadline) {
		t.Fatalf("最后一道闸拦下时应返回 errSyncDeadline，实际 %v", err)
	}
	if ctx.calls != 3 {
		t.Fatalf("writeAndStart 应恰好检查 3 次截止时间，实际 %d 次", ctx.calls)
	}
	if a.mgr.Running(1) {
		t.Fatal("截止后不得拉起进程")
	}
	a.mu.RLock()
	_, hasConnectAt := a.connectAt[1]
	_, hasStartGen := a.startGen[1]
	a.mu.RUnlock()
	if hasConnectAt {
		t.Fatal("最后一道闸拦下时不该登记连接起点：界面会显示一段并不存在的等待")
	}
	if hasStartGen {
		t.Fatal("最后一道闸拦下时不该登记启动代次：迟到的回调会把它当成真启动")
	}
	if got := a.retries[1].attempts; got != 3 {
		t.Fatalf("退避计数 = %d，期望仍是 3：没尝试启动就不该清退避", got)
	}
	if a.appliedConfigOf(1) != "" {
		t.Fatal("最后一道闸拦下时不该记「已应用」：下一轮必须重新拉取")
	}
}
