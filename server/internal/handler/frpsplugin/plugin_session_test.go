package frpsplugin

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// TestRevokedSessionIsNotResurrectedByPing 覆盖「心跳让已撤销的会话重新获得信任」。
//
// 凭据轮换（或重置密码、删号）时，服务端会把数据库会话置为离线、并清掉内存
// 会话。但 frps 的 Ping 回调原先会**无条件**把会话写回 online = true，
// 于是旧 frpc 只要继续心跳就能：
//
//	会话重新变为在线 → FindTrustedClientSession 命中（它还带着刚刷新的
//	last_seen_at）→ resolveUser 认为这是「已完成认证的会话」
//	→ 跳过新客户端密钥校验 → 旧连接继续建代理、继续接受连接。
//
// 会话重新变为在线只能有一条路：新的 Login，或凭据复核通过后的补登记
// （它们都会先验过当前生效的凭据）。
func TestRevokedSessionIsNotResurrectedByPing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:      "test",
		LogLevel: "warn",
		DBDriver: "sqlite",
		DBDSN:    filepath.Join(t.TempDir(), "session.db"),

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
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := service.New(db, cfg)
	// 与 cmd/panel/main.go 一致：准入状态要在处理回调之前加载完。
	// 少了这一步，插件会以「状态未知」拒绝所有放行请求，用例就测不到
	// 它真正关心的凭据与会话逻辑了。
	if !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	h := New(svc, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	u := &model.User{
		Username:     "revoked",
		Password:     "not-used-in-this-test",
		Status:       model.UserStatusActive,
		ClientSecret: "old-secret",
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// 一条真实存在的隧道：让「再建代理」的判定只可能因为**认证**而失败，
	// 不会因为隧道不存在而失败（否则用例可能因为别的原因通过）。
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

	const runID = "run-revoked"
	// 客户端带着**旧**凭据登录成功：会话落库并处于在线状态。
	h.UpsertClientSession(u.ID, u.Username, runID, "1.2.3.4", "0.71", "windows", "amd64")

	var sess model.ClientSession
	if err := db.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if !sess.Online {
		t.Fatal("前置条件：登录后会话应处于在线状态")
	}

	// 轮换接入凭据：会话被置为离线，内存会话被清掉。
	if _, err := svc.ResetClientSecret(u); err != nil {
		t.Fatalf("轮换凭据失败: %v", err)
	}

	// 旧 frpc 继续心跳。
	postPlugin(t, r, fmt.Sprintf(`{"op":"Ping","content":{"user":{"run_id":%q}}}`, runID))

	// 1) 心跳不能把会话改回在线。
	if err := db.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if sess.Online {
		t.Fatal("心跳不能把已撤销的会话改回在线：那会让旧连接重新获得信任")
	}

	// 2) 数据库会话不再被当作可信会话。
	if _, err := svc.FindTrustedClientSession(runID); err == nil {
		t.Fatal("已撤销的会话不该再被当作可信会话")
	}

	// 3) 旧连接再建代理（回调里不带 metas）必须被拒绝。
	body := fmt.Sprintf(
		`{"op":"NewProxy","content":{"user":{"user":%q,"run_id":%q},"proxy_name":%q,"proxy_type":"tcp"}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+".mc")
	res := decodeResponse(t, postPlugin(t, r, body))
	if !res.Reject {
		t.Fatalf("凭据已轮换，旧连接不该还能建代理: %s", body)
	}
}

// TestLoginSessionWriteFailureDoesNotCacheSession 覆盖「会话写库失败仍登记内存」。
//
// 写库失败却把会话记成可信的话，后续 Ping 的准入刷新会因为「查不到可信会话」
// 把它永久拒绝——而缓存命中路径不会重新写库，数据库恢复也救不回来。
// 正确做法是：写库成功才登记，失败就当没登录过，下一次连接重新走凭据复核。
func TestLoginSessionWriteFailureDoesNotCacheSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:          "test",
		LogLevel:     "warn",
		DBDriver:     "sqlite",
		DBDSN:        filepath.Join(t.TempDir(), "login.db"),
		APIKeyEncKey: "test-api-key-enc-key",
	}
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := service.New(db, cfg)
	if !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	h := New(svc, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	u := &model.User{
		Username:     "loginwrite",
		Password:     "not-used",
		Status:       model.UserStatusActive,
		ClientSecret: "secret-for-login",
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	// 模拟「会话表写不进去」：直接删表。
	if err := db.Migrator().DropTable(&model.ClientSession{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	const runID = "run-login-write"
	body := fmt.Sprintf(
		`{"op":"Login","content":{"user":%q,"run_id":%q,"metas":{"%s":%q}}}`,
		service.FrpUserOf(u.ID), runID, service.MetaTokenKey, u.ClientSecret)
	res := decodeResponse(t, postPlugin(t, r, body))
	if res.Reject {
		t.Fatalf("凭据正确时登录本身应放行（只是会话没落库）: %s", body)
	}
	if _, ok := svc.Runtime.LookupSession(runID); ok {
		t.Fatal("会话没写进数据库就不该登记到内存：否则后续 Ping 会把它永久拒绝")
	}
}

// TestCallbacksFailClosedBeforeGuardLoaded 覆盖「准入状态未知」这一档。
//
// 超额与禁用标记只在内存里，由后台采集维护。采集没跑成时（数据库刚起来、
// frps 管理 API 不可达、采样基线读不出来），内存就是空的——而在这套数据结构
// 里，「查不到」与「没超额」完全一样。照常放行等于关掉准入控制，且发生时
// 恰恰是控制面刚重启、所有客户端集中重连的那一刻。
//
// 这里挑的是配额断流的实时拦截点（NewUserConn）：内存里有一条真实会话，
// 状态就绪时这条请求会被放行，因此能证明拦截确实来自准入状态本身。
func TestCallbacksFailClosedBeforeGuardLoaded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:          "test",
		LogLevel:     "warn",
		DBDriver:     "sqlite",
		DBDSN:        filepath.Join(t.TempDir(), "guard.db"),
		APIKeyEncKey: "test-api-key-enc-key",
	}
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	// 刻意**不**调用 LoadAccessGuard：模拟「已经能接回调，但准入状态还没
	// 加载完」的那段窗口。
	svc := service.New(db, cfg)
	h := New(svc, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)

	u := &model.User{
		Username:     "guarduser",
		Password:     "not-used",
		Status:       model.UserStatusActive,
		ClientSecret: "not-used-either",
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	const runID = "run-guard"
	// 真实路径里内存会话是「数据库写入成功之后」才登记的（见 UpsertClientSession）：
	// 两者必须成对出现。这里直接造内存会话，就要把对应的数据库行一起补上，
	// 否则 NewUserConn 的撤销复核会把它判成「已撤销」并拒绝——那测到的是
	// 会话失效，而不是本用例要验证的「准入状态未加载」。
	if err := db.Create(&model.ClientSession{
		UserID:     u.ID,
		Username:   u.Username,
		RunID:      runID,
		Online:     true,
		LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)

	if svc.Runtime.AccessGuardReady() {
		t.Fatal("前置条件：没有加载过准入状态，不该已经是「已知」")
	}

	body := fmt.Sprintf(`{"op":"NewUserConn","content":{"user":{"run_id":%q}}}`, runID)
	if res := decodeResponse(t, postPlugin(t, r, body)); !res.Reject {
		t.Fatal("准入状态尚未加载时不能放行：此时「查不到」与「没超额」无法区分")
	}

	// 加载完成后必须恢复正常，否则这条拒绝会变成永久性的。
	if !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	if res := decodeResponse(t, postPlugin(t, r, body)); res.Reject {
		t.Fatalf("准入状态就绪后应当放行，实际被拒: %s", body)
	}
}
