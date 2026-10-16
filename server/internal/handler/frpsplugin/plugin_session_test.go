package frpsplugin

import (
	"fmt"
	"path/filepath"
	"testing"

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
