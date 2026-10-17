package router

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

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

// 这个文件守的是「单隧道配置按 ID 直查」这条路径的**外部可观察行为**。
//
// 直查是同一条接口上的一次实现替换（原来是全量查询 + 线性扫描），
// 最容易出的偏差不是崩溃，而是语义悄悄变了：少了一条隧道、多给了别人的
// 隧道、或者在归属校验上给出了「存在但不属于你」这种能用来探测 ID 的差别。
// 这些都不会让编译报错，只会让客户端拿到错的那份配置。
//
// 所以这里只断言 HTTP 层的四件事：整份配置仍含全部隧道、单条只含那一条、
// 他人的隧道按不存在处理、非法 ID 仍是参数错误。

func TestClientConfigSingleTunnel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "clientconfig.db"),

		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",

		GatewayHost: "127.0.0.1",
		GatewayPort: 7001,
		AdminPath:   "/admin-console",
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先关连接再让 t.TempDir 清理，否则 Windows 上 sqlite 文件仍被占用。
	defer func() { _ = sqlDB.Close() }()

	if _, err := store.Seed(db, cfg, auth.HashPassword); err != nil {
		t.Fatalf("播种初始数据失败: %v", err)
	}
	svc := service.New(db, cfg)

	// 两个用户各两条隧道：既要有「同一账号内的多条」可比，
	// 也要有一条不属于当前账号的隧道来试归属校验。
	owner := newTestUser(t, db, "cfgowner")
	other := newTestUser(t, db, "cfgother")

	mc1 := newTestTunnel(t, db, owner.ID, "mc1", 20011)
	mc2 := newTestTunnel(t, db, owner.ID, "mc2", 20012)
	otherTunnel := newTestTunnel(t, db, other.ID, "theirs", 20013)

	engine := New(cfg, svc,
		authapi.New(svc, cfg.AdminPath),
		userapi.New(svc),
		adminapi.New(svc),
		frpsplugin.New(svc, cfg.FrpsPluginAllowCIDRs),
	)

	apiKey, _, err := svc.RotateAPIKey(owner.ID)
	if err != nil {
		t.Fatalf("生成 API Key 失败: %v", err)
	}

	fetch := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/user/client/config"+query, nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}

	// 1) 不带 tunnel_id：仍是整份配置，两条隧道都在。
	// 网页端「下载配置」走的就是这条路，不能因为改动收窄成单条。
	rec := fetch("")
	if rec.Code != http.StatusOK {
		t.Fatalf("整份配置返回 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	fullBody := body // 留一份整份配置，下面用来验证「正文不同则摘要不同」
	for _, name := range []string{mc1.Name, mc2.Name} {
		if !strings.Contains(body, `name = "`+name+`"`) {
			t.Fatalf("整份配置里缺少隧道 %q:\n%s", name, body)
		}
	}

	// 2) 带 tunnel_id：只返回这一条，另一条不得出现。
	// 客户端每条隧道一个 frpc 进程，多给一条就等于让两个进程抢同一个代理名。
	rec = fetch("?tunnel_id=" + uintStr(mc1.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("单条配置返回 %d: %s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, `name = "`+mc1.Name+`"`) {
		t.Fatalf("单条配置里没有请求的隧道 %q:\n%s", mc1.Name, body)
	}
	if strings.Contains(body, `name = "`+mc2.Name+`"`) {
		t.Fatalf("单条配置里混进了其他隧道 %q:\n%s", mc2.Name, body)
	}

	// 2.1) 摘要必须**随正文**返回，且等于这份正文的哈希。
	//
	// 客户端拿它判断「本地缓存还要不要刷新」：如果摘要不是由本次正文算出来的，
	// 而是来自另一次清单渲染，客户端就会把「新正文 + 旧摘要」配成一对缓存，
	// 之后可能长期跑着过时配置。
	rev := rec.Header().Get("X-Config-Rev")
	if rev == "" {
		t.Fatal("配置响应必须带 X-Config-Rev（客户端据此跳过未变的拉取）")
	}
	if want := service.FrpcConfigRev(rec.Body.String()); rev != want {
		t.Fatalf("X-Config-Rev 与正文不一致: 头 %q, 正文哈希 %q", rev, want)
	}
	// 不同的正文必须得到不同的摘要（否则「没变」的判断不成立）。
	if rev == service.FrpcConfigRev(fullBody) {
		t.Fatal("单条配置与整份配置的正文不同，摘要不该相同")
	}

	// 3) 他人的隧道 ID：按「不存在」处理，不能返回别人的配置。
	rec = fetch("?tunnel_id=" + uintStr(otherTunnel.ID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("他人隧道 ID 返回 %d（期望 404）: %s", rec.Code, rec.Body.String())
	}

	// 4) ID 写坏了仍是参数错误，不能被当成「不存在」或「全部」。
	for _, raw := range []string{"0", "abc", "-1", "99999999999999999999999"} {
		rec = fetch("?tunnel_id=" + raw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("tunnel_id=%q 返回 %d（期望 400）: %s", raw, rec.Code, rec.Body.String())
		}
	}
}

func newTestUser(t *testing.T, db *gorm.DB, name string) *model.User {
	t.Helper()
	u := &model.User{
		Username: name,
		Password: "not-used-in-this-test",
		Status:   model.UserStatusActive,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户 %s 失败: %v", name, err)
	}
	return u
}

func newTestTunnel(t *testing.T, db *gorm.DB, userID uint, name string, remotePort int) *model.Tunnel {
	t.Helper()
	tunnel := &model.Tunnel{
		UserID:     userID,
		Name:       name,
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: remotePort,
		Status:     model.TunnelStatusActive,
	}
	if err := db.Create(tunnel).Error; err != nil {
		t.Fatalf("建隧道 %s 失败: %v", name, err)
	}
	return tunnel
}

func uintStr(v uint) string {
	return strconv.FormatUint(uint64(v), 10)
}
