package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/client/internal/frpc"
)

// 这一组守的是「对账时哪类失败该退避、哪类不该」。
//
// 两类失败混在一起处理过：配置拉不到也算一次「启动失败」，于是自动同步
// 每 20 秒重试一次就多推一次退避——配置接口恢复之后，客户端还要白白多等
// 最长 5 分钟才把隧道拉起来。而用户看到的现象是「网络早就好了，还是连不上」。

// syncGateHeld 报告同步门闩当前是否被占用。
//
// 门闩是容量 1 的 channel 而不是 Mutex，所以不能用 TryLock 判断：这里尝试
// 放入一个令牌，放得进去说明没人持有（随即取回），放不进去说明正被占用。
func syncGateHeld(a *App) bool {
	select {
	case a.syncGateChan() <- struct{}{}:
		<-a.syncGateChan()
		return false
	default:
		return true
	}
}

// fakePanel 起一个假面板：/info 返回一条启用中的隧道（可切换成空列表），
// /config 的响应由调用方控制，并统计被请求的次数。
func fakePanel(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32, *atomic.Bool) {
	t.Helper()

	var cfgStatus atomic.Int32
	var cfgRequests atomic.Int32
	var noTunnels atomic.Bool
	cfgStatus.Store(http.StatusInternalServerError)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			cfgRequests.Add(1)
			if code := cfgStatus.Load(); code != http.StatusOK {
				w.WriteHeader(int(code))
				return
			}
			// 配置接口返回的是**原文**，不套 {code,data} 外壳。
			_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if noTunnels.Load() {
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[]}}`))
			return
		}
		_, _ = w.Write([]byte(
			`{"code":0,"message":"ok","data":{"username":"u","tunnels":[{"id":1,"name":"mc","type":"tcp","status":"active"}]}}`))
	}))
	t.Cleanup(srv.Close)

	return srv, &cfgStatus, &cfgRequests, &noTunnels
}

func newSyncTestApp(t *testing.T, srv *httptest.Server) *App {
	t.Helper()
	return &App{
		cfg:        &Config{APIKey: "test-key", ServerURL: srv.URL},
		mgr:        frpc.New(filepath.Join(t.TempDir(), "no-such-frpc.exe")),
		applied:    map[uint]string{},
		cfgRev:     map[uint]string{},
		tunnelErrs: map[uint]tunnelErr{},
		retries:    map[uint]*retryState{},
		http:       &http.Client{Timeout: 5 * time.Second},
	}
}

// TestShutdownWaitsForSyncThenClosesManager 覆盖「关停不能漏停同步期间新起的进程」。
//
// 旧实现只调 mgr.StopAll()：同步用的是自己的根上下文，关窗口不会让它停下，
// 它可能正好在 StopAll 之后拿到配置、把 frpc 拉起来——Job Object 绑定失败时
// 那就是一个真正的孤儿进程（端口被占着、隧道还在转发，界面上却已经关了）。
// 现在关停必须是「取消同步 → 等这一轮退出 → 关闸 → 停全部进程」。
func TestShutdownWaitsForSyncThenClosesManager(t *testing.T) {
	a := &App{mgr: frpc.New(filepath.Join(t.TempDir(), "no-such-frpc.exe"))}
	root, cancel := context.WithCancel(context.Background())
	a.syncRoot, a.syncCancel = root, cancel

	// 模拟一轮正在跑的同步：整轮持着同步门闩。
	a.lockSyncBlocking()
	go func() {
		time.Sleep(200 * time.Millisecond)
		a.unlockSync()
	}()

	done := make(chan struct{})
	go func() {
		a.shutdown(context.Background())
		close(done)
	}()

	// 第一步必须是取消同步：在途请求因此立刻返回，退出流程才等得到 syncMu。
	deadline := time.Now().Add(2 * time.Second)
	for root.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if root.Err() == nil {
		t.Fatal("关停必须先取消同步，否则要等每条请求各自的超时，窗口关不掉")
	}

	// 同步还没收工时不能停完进程：它随后起来的进程就漏掉了。
	select {
	case <-done:
		t.Fatal("同步还没退出就完成了关停：同步可能在 StopAll 之后又拉起一个进程")
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("同步退出后关停应立即完成")
	}

	if !a.mgr.Closed() {
		t.Fatal("关停后管理器必须处于关闭状态")
	}
	if err := a.mgr.Start(1, "mc", filepath.Join(t.TempDir(), "frpc.toml")); !errors.Is(err, frpc.ErrClosed) {
		t.Fatalf("关停后再启动进程必须被拒绝，实际: %v", err)
	}
}

// TestRegisteredFlagFlowsIntoState 覆盖「frpc 已连上，界面却还停在连接中」。
//
// 服务端的 online 要等采集（30 秒一轮）+ 客户端同步（20 秒一轮）才更新，
// 用户点完连接会盯着「连接中」等一整轮，误以为连不上。registered 由 frpc 的
// start proxy success 直接置位，界面据此立刻显示「运行中」；服务端采集值
// 继续用于后续校准（掉线、被停用仍以它为准）。
func TestRegisteredFlagFlowsIntoState(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// GetState 只读 a.tunnels（服务端清单由同步填充），这里直接放一条即可。
	a.tunnels = []TunnelVO{{
		ID: 7, Name: "mc", Type: "tcp", Status: tunnelStatusActive,
		LocalIP: "127.0.0.1", LocalPort: 25565,
	}}

	if got := stateTunnel(t, a.GetState(), 7); got.Registered {
		t.Fatal("前置条件：默认不该是「已注册」")
	}

	a.setTunnelRegistered(7, true)
	if got := stateTunnel(t, a.GetState(), 7); !got.Registered {
		t.Error("frpc 报告成功后状态里必须带上 registered，界面才能立刻切成「运行中」")
	}

	a.setTunnelRegistered(7, false)
	if got := stateTunnel(t, a.GetState(), 7); got.Registered {
		t.Error("进程退出或主动停止后必须清掉，否则界面会一直显示「运行中」")
	}
}

// stateTunnel 从状态快照里取出某条隧道。
func stateTunnel(t *testing.T, st State, id uint) TunnelVO {
	t.Helper()
	for _, tv := range st.Tunnels {
		if tv.ID == id {
			return tv
		}
	}
	t.Fatalf("状态里没有隧道 %d", id)
	return TunnelVO{}
}

// TestSyncCleansConfigOfTunnelDeletedElsewhere 覆盖「网页端删除后本地配置残留」。
//
// 隧道可能是在网页端删掉的，或客户端的删除请求在服务端完成之后遇到网络错误：
// 这时客户端这一侧既没有它的进程、也没有内存状态，只清内存的 pruneTunnelState
// 根本不会碰它——磁盘上的 frpc.toml（含接入密钥与 frps token）就一直留着。
func TestSyncCleansConfigOfTunnelDeletedElsewhere(t *testing.T) {
	withTempConfigDir(t)
	srv, cfgStatus, _, noTunnels := fakePanel(t)
	cfgStatus.Store(http.StatusOK)
	a := newSyncTestApp(t, srv)

	// 本地存在隧道 9 的配置，而服务端清单里没有它。
	if err := writeFrpcConfig(9, "token = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	tunnelsDir, err := frpcTunnelsDir()
	if err != nil {
		t.Fatalf("取隧道目录失败: %v", err)
	}
	staleDir := filepath.Join(tunnelsDir, "9")
	noTunnels.Store(true) // 服务端返回空清单

	if _, err := a.applySync(); err != nil {
		t.Fatalf("同步失败: %v", err)
	}

	if _, serr := os.Stat(staleDir); !os.IsNotExist(serr) {
		t.Error("服务端已不存在的隧道，其本地配置应被同步清理（其中含接入密钥）")
	}
}

// TestCleanupWarnedDoesNotGrow 覆盖「提示标记只增不减」。
//
// cleanupWarned 记的是「这条隧道的清理失败已经提示过」。清理成功后不撤掉的话，
// 反复遇到「失败 → 后来成功」的不同隧道，每个 ID 都会永久占一个条目。
func TestCleanupWarnedDoesNotGrow(t *testing.T) {
	withTempConfigDir(t)
	srv, cfgStatus, _, noTunnels := fakePanel(t)
	cfgStatus.Store(http.StatusOK)
	a := newSyncTestApp(t, srv)
	noTunnels.Store(true)

	// 模拟「这条隧道之前提示过清理失败」。
	a.warnConfigCleanup(9, "之前清理失败过")
	if len(a.cleanupWarned) != 1 {
		t.Fatalf("前置条件：应有一条提示标记，实际 %d 条", len(a.cleanupWarned))
	}

	// 文件还在、进程没在跑 → 本轮同步会把它清掉。
	if err := writeFrpcConfig(9, "token = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	if _, err := a.applySync(); err != nil {
		t.Fatalf("同步失败: %v", err)
	}

	if len(a.cleanupWarned) != 0 {
		t.Fatalf("清理成功后应撤掉提示标记，实际还剩 %d 条", len(a.cleanupWarned))
	}
}

// TestPruneTunnelStateDropsCleanupWarn 覆盖提示标记纳入状态裁剪。
func TestPruneTunnelStateDropsCleanupWarn(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	a.warnConfigCleanup(3, "x")
	a.warnConfigCleanup(4, "y")
	a.pruneTunnelState(map[uint]bool{4: true})

	if _, ok := a.cleanupWarned[3]; ok {
		t.Error("服务端已不存在的隧道，其提示标记应被清掉")
	}
	if _, ok := a.cleanupWarned[4]; !ok {
		t.Error("仍然存在的隧道不该被误清")
	}
}

// TestLogoutCleansTunnelConfigsEvenIfMainConfigFails 覆盖「一处失败阻断另一处清理」。
//
// 主配置与隧道配置是两份独立的凭据（API Key vs 接入密钥）。主配置删不掉时
// 直接返回，会让本来能删掉的隧道配置也留在磁盘上——能清掉一个是一个。
func TestLogoutCleansTunnelConfigsEvenIfMainConfigFails(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// 把 config.json 造成一个非空目录：os.Remove 必定失败（两个平台都一样）。
	cfgPath, err := configFilePath()
	if err != nil {
		t.Fatalf("取配置路径失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cfgPath, "sub"), 0o700); err != nil {
		t.Fatalf("构造失败场景失败: %v", err)
	}
	if err := writeFrpcConfig(1, "token = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	tunnelsDir, err := frpcTunnelsDir()
	if err != nil {
		t.Fatalf("取隧道目录失败: %v", err)
	}

	if _, lerr := a.Logout(); lerr == nil {
		t.Fatal("主配置删不掉时应如实报错，而不是当作已退出")
	}

	if _, serr := os.Stat(tunnelsDir); !os.IsNotExist(serr) {
		t.Error("主配置删除失败不该阻断隧道配置清理（其中含接入密钥）")
	}
}

// TestLogoutRemovesAllCredentialFiles 覆盖「退出登录后磁盘上仍留着凭据」。
//
// 主配置里是 API Key，每条隧道的 frpc.toml 里是客户端接入密钥与 frps 全局
// token。只删主配置的话，用户以为「退出了」，换个账号登录后上一个账号的
// 凭据仍然可以被读出来使用。
func TestLogoutRemovesAllCredentialFiles(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// 前置：主配置 + 两条隧道的配置都在磁盘上。
	if err := saveConfig(&Config{APIKey: "secret-key", ServerURL: srv.URL}); err != nil {
		t.Fatalf("保存主配置失败: %v", err)
	}
	for _, id := range []uint{1, 2} {
		if err := writeFrpcConfig(id, "token = \"secret\"\n"); err != nil {
			t.Fatalf("写隧道 %d 配置失败: %v", id, err)
		}
	}

	if _, err := a.Logout(); err != nil {
		t.Fatalf("退出登录失败: %v", err)
	}

	cfgPath, err := configFilePath()
	if err != nil {
		t.Fatalf("取配置路径失败: %v", err)
	}
	if _, serr := os.Stat(cfgPath); !os.IsNotExist(serr) {
		t.Error("退出登录后应删除主配置（其中含 API Key）")
	}
	tunnels, err := frpcTunnelsDir()
	if err != nil {
		t.Fatalf("取隧道目录失败: %v", err)
	}
	if _, serr := os.Stat(tunnels); !os.IsNotExist(serr) {
		t.Error("退出登录后应删除全部隧道配置（其中含接入密钥）")
	}
}

// TestDeleteTunnelRemovesLocalConfig 覆盖「隧道删了、本地配置还留着凭据」。
func TestDeleteTunnelRemovesLocalConfig(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, noTunnels := fakePanel(t)
	a := newSyncTestApp(t, srv)

	if err := writeFrpcConfig(1, "token = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	path, err := frpcConfigPath(1)
	if err != nil {
		t.Fatalf("取隧道配置路径失败: %v", err)
	}

	// 服务端删除成功后就不再返回这条隧道。
	noTunnels.Store(true)
	if _, err := a.DeleteTunnel(1); err != nil {
		t.Fatalf("删除隧道失败: %v", err)
	}

	if _, serr := os.Stat(filepath.Dir(path)); !os.IsNotExist(serr) {
		t.Error("删除隧道后应清掉本地配置（其中含接入密钥）")
	}
}

func TestApplySyncDistinguishesFetchAndStartFailures(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	// 配置会写到 dataDir 下，指向临时目录以免碰真实用户目录。
	withTempConfigDir(t)

	srv, cfgStatus, cfgRequests, noTunnels := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// 1) 配置拉取失败：算同步失败，但**不**推进进程退避。
	if _, err := a.applySync(); err == nil {
		t.Fatal("配置拉不到应作为同步失败返回，而不是静默成功")
	}
	if msg := a.tunnelErrs[1].msg; !strings.Contains(msg, "拉取配置失败") {
		t.Fatalf("隧道应记下失败原因，实际 %q", msg)
	}
	if len(a.retries) != 0 {
		t.Fatal("拉取失败不该推进进程退避：否则配置接口恢复后还要多等最长 5 分钟")
	}

	// 2) 配置拿到了但进程起不来：这类才进入退避。
	cfgStatus.Store(http.StatusOK)
	if _, err := a.applySync(); err == nil {
		t.Fatal("进程起不来同样应作为同步失败返回")
	}
	if msg := a.tunnelErrs[1].msg; !strings.Contains(msg, "启动失败") {
		t.Fatalf("隧道应记下启动失败，实际 %q", msg)
	}
	if len(a.retries) != 1 || a.retryAllowed(1) {
		t.Fatal("启动失败后应进入退避")
	}

	// 3) 退避期间连配置都不该取：省掉一次请求，也避免失败被反复计入。
	before := cfgRequests.Load()
	if _, err := a.applySync(); err != nil {
		t.Fatalf("退避期间不该再产生失败：%v", err)
	}
	if got := cfgRequests.Load(); got != before {
		t.Fatalf("退避期间不应再请求配置（%d → %d）", before, got)
	}

	// 4) 隧道被服务端删掉后，它的各种记录都要清掉。
	//
	// 只按「运行中的进程」清理是不够的：这条隧道恰恰是因为启动失败而没有
	// 进程，它的记录再也不会被访问到。反复「建了、失败、删掉」会让
	// 这几张表一直长下去。
	//
	// applied 也要一起清：它存的是配置原文（每条几 KB），
	// 只在「判断配置有没有变」时用得上，对已删除的隧道没有任何意义。
	a.applied[1] = "serverAddr = \"127.0.0.1\"\n" // 模拟它曾经成功启动过

	noTunnels.Store(true)
	if _, err := a.applySync(); err != nil {
		t.Fatalf("隧道被删掉后不该再有失败：%v", err)
	}
	if len(a.tunnelErrs) != 0 {
		t.Fatalf("已删除隧道的错误记录应被清掉，实际 %v", a.tunnelErrs)
	}
	if len(a.retries) != 0 {
		t.Fatalf("已删除隧道的退避状态应被清掉，实际 %v", a.retries)
	}
	if len(a.applied) != 0 {
		t.Fatalf("已删除隧道的已应用配置文本应被清掉，实际 %v", a.applied)
	}
}

// TestWriteAndStartClearsBackoffBeforeStarting 覆盖「退避清除的时机」。
//
// 清退避必须在启动**之前**：进程退出回调是异步的，frpc 秒退时回调可能已经
// 登记了新退避，启动之后再清会把它抹掉——下一轮同步立刻又拉起进程，
// 退避形同不存在，日志被同样的失败刷屏。
//
// 这条用例把「清除发生在启动之前」变成可观察的行为：已经累计失败 3 次之后
// 再走一次启动（必然失败），失败计数应当重新从 1 开始，而不是继续累加到 4。
func TestWriteAndStartClearsBackoffBeforeStarting(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

	// 先制造 3 次连续失败。
	for i := 0; i < 3; i++ {
		a.noteStartFailure(1, "mc", "启动失败")
	}
	if got := a.retries[1].attempts; got != 3 {
		t.Fatalf("前置条件：失败计数应为 3，实际 %d", got)
	}

	tun := TunnelVO{
		ID: 1, Name: "mc", Type: "tcp", Status: tunnelStatusActive,
		LocalIP: "127.0.0.1", LocalPort: 25565,
	}
	if err := a.writeAndStart(tun, "serverAddr = \"127.0.0.1\"\n"); err == nil {
		t.Fatal("前置条件：frpc 不存在，启动应失败")
	}

	// 调用方（StartTunnel / applySync）在启动失败后会登记一次失败。
	a.noteStartFailure(1, "mc", "启动失败")
	if got := a.retries[1].attempts; got != 1 {
		t.Fatalf("失败计数 = %d，期望 1：说明清退避发生在启动**之前**（旧代码在启动之后，计数会继续累加到 4）", got)
	}
}

// TestApplySyncSkipsUnchangedConfig 覆盖「配置没变还每轮重拉一遍」。
//
// 隧道一多,每轮同步「每条隧道一个 GET」就是主要的耗时与请求量来源。
// 服务端在清单里下发配置摘要(config_rev):摘要一致说明它此刻会生成的字节
// 与本地落盘的那份完全相同,这一轮就不必再拉。
func TestApplySyncSkipsUnchangedConfig(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址,本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	var cfgRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			cfgRequests.Add(1)
			_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[` +
			`{"id":1,"name":"mc","type":"tcp","status":"active","config_rev":"rev-1"}]}}`))
	}))
	defer srv.Close()

	a := newSyncTestApp(t, srv)

	// 测试环境里没有 frpc.exe,启动必然失败并进入退避;那一轮之后隧道就不在
	// 「待处理」里了,请求计数也就无从观察。本用例只关心请求次数,所以每轮
	// 之前清掉退避——退避本身有别的用例守着。
	syncOnce := func() {
		a.clearRetry(1)
		_, _ = a.applySync()
	}

	// 第一轮:本地没有缓存,必须拉一次。
	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("第一轮应拉取 1 次配置,实际 %d", got)
	}

	// 摘要记账只发生在配置**真的落盘**之后(启动失败则两边都不记),
	// 这里直接构造「已经成功应用过一次」的状态——真实路径下一轮成功同步
	// 之后就是这样。
	a.mu.Lock()
	a.applied[1] = "serverAddr = \"127.0.0.1\"\n"
	a.cfgRev[1] = "rev-1"
	a.mu.Unlock()

	// 摘要没变:这一轮不该再发配置请求。
	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("摘要未变时不该再拉配置,实际请求 %d 次", got)
	}

	// 摘要变了:必须重新拉,否则会把旧配置一直跑下去。
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			cfgRequests.Add(1)
			_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n# changed\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[` +
			`{"id":1,"name":"mc","type":"tcp","status":"active","config_rev":"rev-2"}]}}`))
	})
	syncOnce()
	if got := cfgRequests.Load(); got != 2 {
		t.Fatalf("摘要变化后必须重新拉取,实际请求 %d 次", got)
	}
}

// TestOldServerClearsStaleConfigRev 覆盖「新服务端 → 旧服务端」的摘要残留。
//
// 旧服务端的配置响应没有 X-Config-Rev。若这时**保留**之前记下的摘要,
// 它描述的文本可能已经过期:期间配置从 A 改到 B、又回到 A 之后,客户端会
// 拿那条旧摘要命中缓存,把 B 的正文当成 A 用下去,而且没有任何报错。
// 所以收到正文却没有摘要时,必须把该隧道的旧摘要清掉,退回逐轮拉取。
func TestOldServerClearsStaleConfigRev(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址,本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	const body = "serverAddr = \"127.0.0.1\"\n"
	var (
		sendListRev atomic.Bool
		sendCfgRev  atomic.Bool
		cfgRequests atomic.Int32
	)
	sendListRev.Store(false) // 先当作旧服务端
	sendCfgRev.Store(false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			cfgRequests.Add(1)
			if sendCfgRev.Load() {
				w.Header().Set(configRevHeader, "rev-A")
			}
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rev := ""
		if sendListRev.Load() {
			rev = `,"config_rev":"rev-A"`
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[` +
			`{"id":1,"name":"mc","type":"tcp","status":"active"` + rev + `}]}}`))
	}))
	defer srv.Close()

	a := newSyncTestApp(t, srv)
	// 本地已有一份「成功应用过」的记账(applied=A, 摘要 rev-A),
	// 这是新服务端时期留下来的。
	a.mu.Lock()
	a.applied[1] = body
	a.cfgRev[1] = "rev-A"
	a.mu.Unlock()

	syncOnce := func() {
		a.clearRetry(1)
		_, _ = a.applySync()
	}

	// 旧服务端:正文照旧是 A(本地已是 A,不会触发重启),但没有摘要头。
	syncOnce()
	if rev, ok := a.cfgRev[1]; ok {
		t.Fatalf("没有 X-Config-Rev 时必须清除旧摘要,实际仍是 %q", rev)
	}

	// 服务端换回新版(清单重新带上 rev-A):摘要已被清掉,必须重新拉取,
	// 而不是凭「清单说 rev-A、本地也曾记过 rev-A」直接命中。
	cfgRequests.Store(0)
	sendListRev.Store(true)
	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("摘要被清掉后应重新拉取一次,实际请求 %d 次", got)
	}
}

// TestFetchTunnelConfigUsesServedRev 覆盖「摘要与正文必须同源」。
//
// 清单里的 config_rev 是**另一次**渲染算出来的,中间隔着一次网络往返。
// 管理端在这期间改了隧道的话,若把清单摘要与新正文配成一对缓存,下一轮
// 就可能误判「没变」而一直跑旧配置。所以摘要一律取配置响应自带的
// X-Config-Rev;老服务端没有这个头时宁可不记账(返回空串)。
func TestFetchTunnelConfigUsesServedRev(t *testing.T) {
	var withHeader atomic.Bool
	withHeader.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withHeader.Load() {
			w.Header().Set(configRevHeader, "rev-from-body")
		}
		_, _ = w.Write([]byte("serverAddr = \"127.0.0.1\"\n"))
	}))
	defer srv.Close()

	a := &App{http: &http.Client{Timeout: 5 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	text, rev, err := a.fetchTunnelConfig(ctx, srv.URL, "k", 1)
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if rev != "rev-from-body" {
		t.Fatalf("摘要必须取自本次响应,实际 %q", rev)
	}
	if !strings.Contains(text, "serverAddr") {
		t.Fatalf("正文解析错误: %q", text)
	}

	// 老服务端:没有头 → 空摘要 → 调用方不记账,保持逐轮拉取。
	withHeader.Store(false)
	_, rev, err = a.fetchTunnelConfig(ctx, srv.URL, "k", 1)
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if rev != "" {
		t.Fatalf("没有响应头时摘要应为空(否则会拿清单摘要冒充),实际 %q", rev)
	}
}

// TestApplySyncTreatsEmptyConfigAsFailure 覆盖「空配置被当成成功」。
//
// 静默跳过的话这一轮会被记成完全成功（SyncErr 清空、LastSyncAt 更新），
// 而那条隧道什么都没连上，界面上也没有任何原因——用户只能看着
// 一个「连接中」，等多久都不会变。
func TestApplySyncTreatsEmptyConfigAsFailure(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			// 200 但内容为空。
			_, _ = w.Write([]byte("   \n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(
			`{"code":0,"message":"ok","data":{"username":"u","tunnels":[{"id":1,"name":"mc","type":"tcp","status":"active"}]}}`))
	}))
	defer srv.Close()

	a := newSyncTestApp(t, srv)
	if _, err := a.applySync(); err == nil {
		t.Fatal("空配置必须作为同步失败返回，而不是被当成成功跳过")
	}
	if msg := a.tunnelErrs[1].msg; !strings.Contains(msg, "未返回该隧道的配置") {
		t.Fatalf("隧道应记下原因，实际 %q", msg)
	}
	if len(a.retries) != 0 {
		t.Fatal("空配置属于同步问题，不该推进进程退避")
	}
}
