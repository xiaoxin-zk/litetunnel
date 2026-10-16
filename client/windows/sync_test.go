package main

import (
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
		tunnelErrs: map[uint]tunnelErr{},
		retries:    map[uint]*retryState{},
		http:       &http.Client{Timeout: 5 * time.Second},
	}
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
