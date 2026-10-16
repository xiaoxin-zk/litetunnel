package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/adminapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/authapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/frpsplugin"
	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/userapi"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// 这个文件补的是「解析成功但状态没真正生效」这一类缺陷的缺口。
//
// service 包里的单测只覆盖到 ListProxies 的解析与 phase → bool 的判定。
// 从解析结果到接口字段之间还有三段：采集器把结果写进运行态、handler 把它
// 读出来、JSON 里叫 online。任何一段断掉，隧道在界面上都显示「连接中」，
// 而所有单元测试仍然是绿的——这次的故障正是这个形态（envelope 没解开时
// 就是这样，一路静默）。

// fakeFrps 是一个可以切换返回内容的假 frps 管理接口。
type fakeFrps struct {
	*httptest.Server

	mu       sync.Mutex
	mode     string // online / garbage
	proxy    string // 形如 lt_u1.mc
	requests int
}

func newFakeFrps() *fakeFrps {
	f := &fakeFrps{mode: "online"}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		mode, proxy := f.mode, f.proxy
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if mode == "garbage" {
			_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
			return
		}
		// frps v0.71 的真实形状：成功码 200，分页对象包在 data 里。
		fmt.Fprintf(w,
			`{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":%q,"user":"lt_u1","clientID":"fake","status":{"phase":"online","todayTrafficIn":0,"todayTrafficOut":0,"curConns":0}}]}}`,
			proxy)
	}))
	return f
}

func (f *fakeFrps) setMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

func (f *fakeFrps) setProxy(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxy = name
}

func (f *fakeFrps) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// syncBuffer 是并发安全的日志缓冲：采集器在后台协程里写日志。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTunnelOnlineReachesClientAPI 断言「frps 上报在线」能一路走到接口字段。
//
// 链路：假 frps 响应 → ListProxies 解析 → collectTraffic 写入运行态 →
// /api/user/client/info 的 tunnels[].online。
func TestTunnelOnlineReachesClientAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 捕获日志：既断言「采集失败被记录」，也用它确认那一轮采集真的处理完了
	// （请求计数只能证明请求发出，证明不了处理结束）。
	var logs syncBuffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)

	frps := newFakeFrps()
	defer frps.Close()

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "tunnelonline.db"),

		FrpsAPIAddr:     frps.URL,
		FrpsAPIUser:     "admin",
		FrpsAPIPassword: "secret",

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",

		// 采集器把小于 5 秒的间隔抬到 5 秒，这里就用最小值。
		TrafficPollInterval: 5 * time.Second,
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if _, err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		t.Fatalf("播种初始数据失败: %v", err)
	}
	svc := service.New(db, cfg)

	// 一条真实存在的用户与隧道：采集器只认库里的 (用户 ID, 隧道名)。
	u := &model.User{
		Username: "tunnelonline",
		Password: "not-used-in-this-test",
		Status:   model.UserStatusActive,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tunnel := &model.Tunnel{
		UserID:     u.ID,
		Name:       "mc",
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: 20001,
		Status:     model.TunnelStatusActive,
	}
	if err := db.Create(tunnel).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	// frps 上报的是规范化后的代理名 <user>.<隧道名>。
	frps.setProxy(service.FrpUserOf(u.ID) + "." + tunnel.Name)

	ctx, cancel := context.WithCancel(context.Background())
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先停采集器再关连接：否则临时目录里的 sqlite 文件在测试结束时仍被占用，
	// t.TempDir 的清理会失败（Windows 上尤其明显）。
	defer func() {
		cancel()
		_ = sqlDB.Close()
	}()

	// 采集器启动即跑一次，所以这里不必等 5 秒的轮询周期。
	svc.StartTrafficCollector(ctx)

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)

	apiKey, _, err := svc.RotateAPIKey(u.ID)
	if err != nil {
		t.Fatalf("生成 API Key 失败: %v", err)
	}

	// ---- 1) frps 报 online，接口必须给出 online=true ----
	waitOnline(t, engine, apiKey, tunnel.Name, true)

	// ---- 2) 响应读不懂时必须保留上次状态，而不是整体翻成离线 ----
	before := frps.requestCount()
	frps.setMode("garbage")

	// 等一轮采集真正处理完：日志里出现「保留上次在线状态」即为处理结束。
	waitForLog(t, &logs, "保留上次在线状态", 10*time.Second)
	if got := frps.requestCount(); got <= before {
		t.Fatalf("假 frps 未收到新一轮请求（%d → %d）", before, got)
	}

	waitOnline(t, engine, apiKey, tunnel.Name, true)
}

// getTunnelOnline 请求客户端接入信息接口，取出指定隧道的 online 字段。
func getTunnelOnline(t *testing.T, engine *gin.Engine, apiKey, name string) (bool, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/user/client/info", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("接入信息接口返回 %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		Data struct {
			Tunnels []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
				Online bool   `json:"online"`
			} `json:"tunnels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("接入信息响应不是合法 JSON: %v", err)
	}
	for _, tn := range out.Data.Tunnels {
		if tn.Name == name {
			if tn.Status != model.TunnelStatusActive {
				t.Fatalf("隧道 %s 的 status = %q，期望 %q", name, tn.Status, model.TunnelStatusActive)
			}
			return tn.Online, rec.Body.String()
		}
	}
	t.Fatalf("接入信息里没有隧道 %q: %s", name, rec.Body.String())
	return false, ""
}

// waitOnline 轮询接口直到 online 达到期望值。
//
// 采集在后台协程里跑，与测试的请求存在竞争，所以必须轮询而不是断言一次。
// 重试次数刻意压得很小：该接口走的是真实限流中间件（默认突发容量 60），
// 轮询过密会把自己限流成 429。
func waitOnline(t *testing.T, engine *gin.Engine, apiKey, name string, want bool) {
	t.Helper()

	var last string
	for i := 0; i < 15; i++ {
		online, raw := getTunnelOnline(t, engine, apiKey, name)
		last = raw
		if online == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("等待隧道 %s 的 online=%v 超时，最后一次响应: %s", name, want, last)
}

// waitForLog 等到日志里出现指定片段。
func waitForLog(t *testing.T, logs *syncBuffer, want string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if contains(logs.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待日志 %q 超时，当前日志:\n%s", want, logs.String())
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
