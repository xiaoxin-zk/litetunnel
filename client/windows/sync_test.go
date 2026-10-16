package main

import (
	"net/http"
	"net/http/httptest"
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
