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

// TestWriteAndStartSkipsWorkAfterDeadline 覆盖「超时之后仍写配置并拉起进程」。
//
// 本轮同步已经报超时，而某条隧道的配置正文是在超时之前取到的、之后才轮到
// 处理。照旧落盘并启动的话，界面上写着「本轮同步超时」，实际进程已经起来了
// ——两端说法互相矛盾；更糟的是下一轮同步会把这条已在跑的进程当作「已运行」
// 跳过，那条错误提示就一直挂着，再没有人去纠正它。
//
// 断言三件事：不落盘、不启动、返回的是哨兵错误（调用方据此区分「没轮到」
// 与「启动失败」——后者会推进退避，前者不会）。
func TestWriteAndStartSkipsWorkAfterDeadline(t *testing.T) {
	dir := withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 先让它处于退避中：超时路径连退避都不该动（既不推进、也不清掉）。
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
	// 连目录都不该建：frpcConfigPath 有「顺手建目录」的副作用，
	// 所以第一道闸必须在它前面，否则超时之后仍会在磁盘上留下空目录。
	if _, statErr := os.Stat(filepath.Join(dir, "tunnels", "1", "frpc.toml")); statErr == nil {
		t.Fatal("超时后不得落盘配置：那一份配置既没被应用也没被记账")
	}
	// 退避原封不动：说明根本没走到「启动前清退避」那一步。
	if got := a.retries[1].attempts; got != 3 {
		t.Fatalf("退避计数 = %d，期望仍是 3：超时路径不该改动退避状态", got)
	}
}

// TestApplySyncDeadlineDoesNotCountTunnelAsFailed 覆盖「超时被当成隧道失败」。
//
// 配置接口全部挂住时，本轮应只报「超时」这一条。若把截止时间跳过的隧道也
// 记进 failures，日志里会多出一串「启动失败」「拉取配置失败」——那些隧道
// 什么都没做错，只是没轮到。用户会以为隧道本身有问题，去改配置、重装，
// 而下一轮它明明自己就好了。
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
	// 错误里只能有「超时」这一条汇总，不能带「N 条隧道同步失败」。
	if strings.Contains(err.Error(), "隧道同步失败") {
		t.Fatalf("超时跳过的隧道不是失败，不该计入失败条数：%v", err)
	}
	if strings.Contains(err.Error(), "另有") {
		t.Fatalf("超时路径不应追加失败明细：%v", err)
	}
	// 一条都不该进退避：它们没启动过，也就谈不上启动失败。
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

// ---- 游标只按「落定」推进（缺陷 2） ----

// TestSyncCursorStopsAtFirstUnappliedTunnel 覆盖「派发出去但没应用的隧道被跳过」。
//
// 构造：前 fast 条隧道配置秒回、能被正常应用（启动失败也算落定——失败已经
// 记进退避）；后面几条的配置请求挂住，等前几条处理完之后取消本轮预算。
//
// 旧实现按**派发数**推进游标：派发出去的隧道即使因为截止时间一条都没应用，
// 也已经被算作「处理过」，游标于是越过它们。被越过的隧道要等整整一圈才会
// 再被看到——隧道多、轮次又被截止时间砍短时就是好几分钟，用户侧表现为
// 「隧道一直离线，重启客户端也没用」。
//
// 新实现只按落定推进：游标应停在第一条没落定的隧道上（下标 fast）。
func TestSyncCursorStopsAtFirstUnappliedTunnel(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	const (
		fast  = 5
		total = 12
	)

	var fastReplied atomic.Int32

	// 本轮预算由测试自己控制：不使用整轮超时，而是在「前几条都已落定」之后
	// 主动取消，从而精确复现「派发成功、应用被截止时间砍掉」的窗口。
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
		// 挂到本轮被取消：模拟「请求还没回来，截止时间先到」。
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

	// 等前几条真的落定（启动失败 → 记进退避），再取消。
	// 用 retryAllowed 观察而不是固定 sleep：它拿的是同一把锁，读到 false
	// 就说明 noteStartFailure 已经执行，即 failStart 已经发生（落定）。
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
		// 留一点余量让 settle 记账落定（它紧跟在 applyCfg 返回之后）。
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, _ = a.applySyncData(ctx, &clientInfoData{Username: "u", Tunnels: tunnels}, 1)
	<-done

	// 游标应停在第一条没落定的隧道（下标 fast，即 id=fast+1）。
	// 旧实现会推到「派发到的最后一条之后」，也就是 total（回绕到 0）附近。
	if a.syncStart != fast {
		t.Fatalf("续传位置 = %d，期望 %d：游标必须停在第一条没落定的隧道上，"+
			"按派发数推进会越过它们，让它们整整一轮不再被处理", a.syncStart, fast)
	}
	// 被截止时间砍掉的隧道不是失败：不该有失败记录，也不该进退避。
	for i := fast + 1; i <= total; i++ {
		if st, ok := a.retries[uint(i)]; ok && st != nil {
			t.Fatalf("隧道 %d 因截止时间未处理，却被记了退避 %+v", i, st)
		}
		if e, ok := a.tunnelErrs[uint(i)]; ok && e.msg != "" {
			t.Fatalf("隧道 %d 因截止时间未处理，却被记了失败原因 %q", i, e.msg)
		}
	}
}

// TestSyncRoundNextStart 覆盖游标落点的三种情况（纯函数，无网络）。
//
// 这是缺陷 2 的核心判据，单独测它可以把「环形下标」的算术钉死，
// 不必依赖网络时序。
func TestSyncRoundNextStart(t *testing.T) {
	const n = 6
	order := make([]TunnelVO, n)
	for i := range order {
		order[i] = TunnelVO{ID: uint(i + 1)}
	}
	// 派发顺序覆盖全部 6 条（下标 0..5）。
	allPos := []int{0, 1, 2, 3, 4, 5}

	cases := []struct {
		name    string
		rot     int
		settle  []int // 落定的下标
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

// ---- 最后一道截止闸紧贴启动（缺陷 3） ----

// gateCtx 是一个「第 errAt 次 Err() 调用开始报错」的 context。
//
// writeAndStart 只用 ctx.Err() 判断截止时间，所以可以用它把「第几道闸」
// 精确地打出来——真实的超时无法稳定地卡在两道闸之间。
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

// TestWriteAndStartFinalGateLeavesNoState 覆盖「最后一道闸拦下时留下脏状态」。
//
// 前两道闸都通过（否则测不到最后一道），第三道报错。此时必须：
//   - 返回 errSyncDeadline（调用方据此不记失败、不推进退避）；
//   - 不登记连接起点（否则界面会显示一段并不存在的等待）；
//   - 不登记启动代次（否则迟到的退出回调会把它当成一次真启动的产物）；
//   - 不清退避（这一轮根本没尝试启动，清掉等于把正在退避的隧道提前放行）。
func TestWriteAndStartFinalGateLeavesNoState(t *testing.T) {
	withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// 先让它处于退避中，用来验证最后一道闸之后不会清退避。
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
