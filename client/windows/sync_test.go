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

func syncGateHeld(a *App) bool {
	select {
	case a.syncGateChan() <- struct{}{}:
		<-a.syncGateChan()
		return false
	default:
		return true
	}
}

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

func TestShutdownWaitsForSyncThenClosesManager(t *testing.T) {
	a := &App{mgr: frpc.New(filepath.Join(t.TempDir(), "no-such-frpc.exe"))}
	root, cancel := context.WithCancel(context.Background())
	a.syncRoot, a.syncCancel = root, cancel

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

	deadline := time.Now().Add(2 * time.Second)
	for root.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if root.Err() == nil {
		t.Fatal("关停必须先取消同步，否则要等每条请求各自的超时，窗口关不掉")
	}

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

func TestRegisteredFlagFlowsIntoState(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

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

func TestSyncCleansConfigOfTunnelDeletedElsewhere(t *testing.T) {
	withTempConfigDir(t)
	srv, cfgStatus, _, noTunnels := fakePanel(t)
	cfgStatus.Store(http.StatusOK)
	a := newSyncTestApp(t, srv)

	if err := writeFrpcConfig(9, "token = \"secret\"\n"); err != nil {
		t.Fatalf("写隧道配置失败: %v", err)
	}
	tunnelsDir, err := frpcTunnelsDir()
	if err != nil {
		t.Fatalf("取隧道目录失败: %v", err)
	}
	staleDir := filepath.Join(tunnelsDir, "9")
	noTunnels.Store(true)

	if _, err := a.applySync(); err != nil {
		t.Fatalf("同步失败: %v", err)
	}

	if _, serr := os.Stat(staleDir); !os.IsNotExist(serr) {
		t.Error("服务端已不存在的隧道，其本地配置应被同步清理（其中含接入密钥）")
	}
}

func TestCleanupWarnedDoesNotGrow(t *testing.T) {
	withTempConfigDir(t)
	srv, cfgStatus, _, noTunnels := fakePanel(t)
	cfgStatus.Store(http.StatusOK)
	a := newSyncTestApp(t, srv)
	noTunnels.Store(true)

	a.warnConfigCleanup(9, "之前清理失败过")
	if len(a.cleanupWarned) != 1 {
		t.Fatalf("前置条件：应有一条提示标记，实际 %d 条", len(a.cleanupWarned))
	}

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

func TestLogoutCleansTunnelConfigsEvenIfMainConfigFails(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

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

func TestLogoutRemovesAllCredentialFiles(t *testing.T) {
	withTempConfigDir(t)
	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

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
	withTempConfigDir(t)

	srv, cfgStatus, cfgRequests, noTunnels := fakePanel(t)
	a := newSyncTestApp(t, srv)

	if _, err := a.applySync(); err == nil {
		t.Fatal("配置拉不到应作为同步失败返回，而不是静默成功")
	}
	if msg := a.tunnelErrs[1].msg; !strings.Contains(msg, "拉取配置失败") {
		t.Fatalf("隧道应记下失败原因，实际 %q", msg)
	}
	if len(a.retries) != 0 {
		t.Fatal("拉取失败不该推进进程退避：否则配置接口恢复后还要多等最长 5 分钟")
	}

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

	before := cfgRequests.Load()
	if _, err := a.applySync(); err != nil {
		t.Fatalf("退避期间不该再产生失败：%v", err)
	}
	if got := cfgRequests.Load(); got != before {
		t.Fatalf("退避期间不应再请求配置（%d → %d）", before, got)
	}

	a.applied[1] = "serverAddr = \"127.0.0.1\"\n"

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

func TestWriteAndStartClearsBackoffBeforeStarting(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	srv, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, srv)

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
	if err := a.writeAndStart(context.Background(), tun, "serverAddr = \"127.0.0.1\"\n"); err == nil {
		t.Fatal("前置条件：frpc 不存在，启动应失败")
	}

	a.noteStartFailure(1, "mc", "启动失败")
	if got := a.retries[1].attempts; got != 1 {
		t.Fatalf("失败计数 = %d，期望 1：说明清退避发生在启动**之前**（旧代码在启动之后，计数会继续累加到 4）", got)
	}
}

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

	syncOnce := func() {
		a.clearRetry(1)
		_, _ = a.applySync()
	}

	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("第一轮应拉取 1 次配置,实际 %d", got)
	}

	a.mu.Lock()
	a.applied[1] = "serverAddr = \"127.0.0.1\"\n"
	a.cfgRev[1] = "rev-1"
	a.mu.Unlock()

	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("摘要未变时不该再拉配置,实际请求 %d 次", got)
	}

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
	sendListRev.Store(false)
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
	a.mu.Lock()
	a.applied[1] = body
	a.cfgRev[1] = "rev-A"
	a.mu.Unlock()

	syncOnce := func() {
		a.clearRetry(1)
		_, _ = a.applySync()
	}

	syncOnce()
	if rev, ok := a.cfgRev[1]; ok {
		t.Fatalf("没有 X-Config-Rev 时必须清除旧摘要,实际仍是 %q", rev)
	}

	cfgRequests.Store(0)
	sendListRev.Store(true)
	syncOnce()
	if got := cfgRequests.Load(); got != 1 {
		t.Fatalf("摘要被清掉后应重新拉取一次,实际请求 %d 次", got)
	}
}

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

	withHeader.Store(false)
	_, rev, err = a.fetchTunnelConfig(ctx, srv.URL, "k", 1)
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if rev != "" {
		t.Fatalf("没有响应头时摘要应为空(否则会拿清单摘要冒充),实际 %q", rev)
	}
}

func TestApplySyncTreatsEmptyConfigAsFailure(t *testing.T) {
	if defaultServerURL() != "" {
		t.Skip("当前构建注入了服务端地址，本用例需要自己控制服务端")
	}
	withTempConfigDir(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
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
