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

func newPluginTestHandler(t *testing.T, dbName string, loadGuard bool) (*service.Services, *Handler, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Env:            "test",
		LogLevel:       "warn",
		DBDriver:       "sqlite",
		DBDSN:          filepath.Join(t.TempDir(), dbName),
		UserJWTSecret:  "test-user-secret",
		AdminJWTSecret: "test-admin-secret",
		APIKeyEncKey:   "test-api-key-enc-key",
		GatewayHost:    "127.0.0.1",
		GatewayPort:    7001,
		AdminPath:      "/admin-console",
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
	if loadGuard && !svc.LoadAccessGuard() {
		t.Fatal("加载准入状态失败")
	}
	h := New(svc, nil)
	r := gin.New()
	r.POST("/plugin", h.Handle)
	return svc, h, r
}

func mustPluginUser(t *testing.T, svc *service.Services, username, secret string) *model.User {
	t.Helper()
	u := &model.User{
		Username:     username,
		Password:     "not-used-in-this-test",
		Status:       model.UserStatusActive,
		ClientSecret: secret,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	return u
}

func mustPluginTunnel(t *testing.T, svc *service.Services, u *model.User, name string, remotePort int) {
	t.Helper()
	tn := &model.Tunnel{
		UserID:     u.ID,
		Name:       name,
		Type:       model.ProxyTypeTCP,
		LocalIP:    "127.0.0.1",
		LocalPort:  25565,
		RemotePort: remotePort,
		Status:     model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tn).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
}

func mustPluginSession(t *testing.T, svc *service.Services, u *model.User, runID string) {
	t.Helper()
	if err := svc.DB.Create(&model.ClientSession{
		UserID:     u.ID,
		Username:   u.Username,
		RunID:      runID,
		Online:     true,
		LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	svc.Runtime.RecordLogin(runID, u.ID, u.Username)
}

func newProxyBody(u *model.User, runID, tunnelName string, remotePort int) string {
	return fmt.Sprintf(
		`{"op":"NewProxy","content":{"user":{"user":%q,"run_id":%q},`+
			`"proxy_name":%q,"proxy_type":"tcp","remote_port":%d}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+"."+tunnelName, remotePort)
}

func newUserConnBody(u *model.User, runID, tunnelName string) string {
	return fmt.Sprintf(
		`{"op":"NewUserConn","content":{"user":{"user":%q,"run_id":%q},`+
			`"proxy_name":%q,"proxy_type":"tcp"}}`,
		service.FrpUserOf(u.ID), runID, service.FrpUserOf(u.ID)+"."+tunnelName)
}

func markBlocked(svc *service.Services, userID uint) {
	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetUserBlocked(userID, true)
}

func TestNewProxyFallbackDeniesBlockedUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "blocked.db", true)
	u := mustPluginUser(t, svc, "blockeduser", "secret-blocked")
	mustPluginTunnel(t, svc, u, "mc", 21001)

	const runID = "run-blocked"
	mustPluginSession(t, svc, u, runID)

	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}
	markBlocked(svc, u.ID)
	if !svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：禁用标记必须已置位")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21001)))
	if !res.Reject {
		t.Fatal("账号已被禁用、会话快照未命中时，fallback 路径必须拒绝注册（缺陷 5）")
	}
}

func TestNewProxyFallbackDeniesExceededUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "exceeded.db", true)
	u := mustPluginUser(t, svc, "exceededuser", "secret-exceeded")
	mustPluginTunnel(t, svc, u, "mc", 21002)

	const runID = "run-exceeded"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}

	svc.Runtime.BumpGuardVer()
	svc.Runtime.SetQuotaExceeded(u.ID, true)
	if svc.Runtime.IsUserBlocked(u.ID) {
		t.Fatal("前置条件：本用例只应触发超额，不该同时是禁用状态")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21002)))
	if !res.Reject {
		t.Fatal("超额账号在 fallback 路径上必须拒绝注册")
	}
}

func TestNewProxyFallbackAllowsActiveUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "active.db", true)
	u := mustPluginUser(t, svc, "activeuser", "secret-active")
	mustPluginTunnel(t, svc, u, "mc", 21003)

	const runID = "run-active"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该 run_id 不该有会话级准入快照")
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21003)))
	if res.Reject {
		t.Fatalf("正常账号在 fallback 路径上必须放行，实际被拒（%s）", res.RejectReason)
	}
}

func TestNewProxyDeniesUserDisabledByAdmin(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "admin-disabled.db", true)
	u := mustPluginUser(t, svc, "adminblocked", "secret-admin")
	mustPluginTunnel(t, svc, u, "mc", 21005)

	const runID = "run-admin-blocked"
	mustPluginSession(t, svc, u, runID)

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用账号失败: %v", err)
	}

	res := decodeResponse(t, postPlugin(t, r, newProxyBody(u, runID, "mc", 21005)))
	if !res.Reject {
		t.Fatal("管理员禁用之后必须拒绝注册新代理")
	}
}

func TestLocalAdmissionReportsUnready(t *testing.T) {
	svc, h, _ := newPluginTestHandler(t, "unready.db", false)
	u := mustPluginUser(t, svc, "unreadyuser", "secret-unready")

	if svc.Runtime.AccessGuardReady() {
		t.Fatal("前置条件：没有加载过准入状态，不该已经是「已知」")
	}
	if _, _, ok := h.localAdmission(u.ID); ok {
		t.Fatal("准入状态未加载时必须报告「无法判定」，不能返回一份空表算出来的正常状态")
	}
}

func TestLocalAdmissionReadsStableSnapshot(t *testing.T) {
	svc, h, _ := newPluginTestHandler(t, "stable.db", true)
	u := mustPluginUser(t, svc, "stableuser", "secret-stable")

	blocked, exceeded, ok := h.localAdmission(u.ID)
	if !ok {
		t.Fatal("准入版本稳定时必须能读到可信判定")
	}
	if blocked || exceeded {
		t.Fatalf("正常账号不该被判定为禁用/超额（blocked=%v exceeded=%v）", blocked, exceeded)
	}

	markBlocked(svc, u.ID)
	blocked, exceeded, ok = h.localAdmission(u.ID)
	if !ok {
		t.Fatal("准入版本稳定时必须能读到可信判定")
	}
	if !blocked || exceeded {
		t.Fatalf("禁用后应只报告 blocked（blocked=%v exceeded=%v）", blocked, exceeded)
	}
}

func TestNewUserConnFallbackDeniesBlockedUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "connblocked.db", true)
	u := mustPluginUser(t, svc, "connblocked", "secret-conn")
	mustPluginTunnel(t, svc, u, "mc", 21004)

	const runID = "run-conn-blocked"
	mustPluginSession(t, svc, u, runID)

	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该会话不该已经建立准入快照")
	}
	markBlocked(svc, u.ID)

	res := decodeResponse(t, postPlugin(t, r, newUserConnBody(u, runID, "mc")))
	if !res.Reject {
		t.Fatal("账号已被禁用、会话快照未命中时，NewUserConn 的 fallback 路径必须拒绝新建连接")
	}
}

func TestNewUserConnFallbackAllowsActiveUser(t *testing.T) {
	svc, _, r := newPluginTestHandler(t, "connactive.db", true)
	u := mustPluginUser(t, svc, "connactive", "secret-conn-active")
	mustPluginTunnel(t, svc, u, "mc", 21006)

	const runID = "run-conn-active"
	mustPluginSession(t, svc, u, runID)
	if _, _, ok := svc.SessionGuard(runID); ok {
		t.Fatal("前置条件：该会话不该已经建立准入快照")
	}

	res := decodeResponse(t, postPlugin(t, r, newUserConnBody(u, runID, "mc")))
	if res.Reject {
		t.Fatalf("正常账号（快照未命中）必须放行新建连接，实际被拒（%s）", res.RejectReason)
	}
}
