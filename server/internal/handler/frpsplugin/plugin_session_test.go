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
	h.UpsertClientSession(u.ID, u.Username, runID, "1.2.3.4", "0.71", "windows", "amd64")

	var sess model.ClientSession
	if err := db.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if !sess.Online {
		t.Fatal("前置条件：登录后会话应处于在线状态")
	}

	if _, err := svc.ResetClientSecret(u); err != nil {
		t.Fatalf("轮换凭据失败: %v", err)
	}

	postPlugin(t, r, fmt.Sprintf(`{"op":"Ping","content":{"user":{"run_id":%q}}}`, runID))

	if err := db.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatalf("读会话失败: %v", err)
	}
	if sess.Online {
		t.Fatal("心跳不能把已撤销的会话改回在线：那会让旧连接重新获得信任")
	}

	if _, err := svc.FindTrustedClientSession(runID); err == nil {
		t.Fatal("已撤销的会话不该再被当作可信会话")
	}

	body := fmt.Sprintf(
		`{"op":"NewProxy","content":{"user":{"user":%q,"run_id":%q},"proxy_name":%q,"proxy_type":"tcp"}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+".mc")
	res := decodeResponse(t, postPlugin(t, r, body))
	if !res.Reject {
		t.Fatalf("凭据已轮换，旧连接不该还能建代理: %s", body)
	}
}

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

	if !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	if res := decodeResponse(t, postPlugin(t, r, body)); res.Reject {
		t.Fatalf("准入状态就绪后应当放行，实际被拒: %s", body)
	}
}
