package service

// 这个文件守的是「账号生命周期的最后一公里」：
//
//   - 删号/注销之后，frps 上已经建立的代理必须被主动关掉，而不是等客户端自己退出；
//   - 禁用账号时，数据库里的会话必须在**同一个事务**里置为离线，否则别的实例
//     仍会按 online=true 的会话放行新连接；
//   - 代理缺少实例身份字段（clientID / lastStartAt 都为空）时宁可跳过，
//     也不能按名字盲关——那会误杀客户端刚重建的同名代理。
//
// 全部离线运行：假 frps 用 httptest，数据库用临时 sqlite（见 newTestServices）。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// fakeFrpsProxies 是一个可断言、可注入故障的假 frps 管理接口。
//
// 只实现断流用到的两个动作：GET 列表与 DELETE 关闭。items 是列表里各条代理的
// JSON 片段（原样拼进去），使每个用例都能精确控制「frps 报告了哪些代理、
// 它们带哪些身份字段」。
type fakeFrpsProxies struct {
	mu     sync.Mutex
	items  []string
	closed []string
	// failAll 为真时所有请求都返回 500，模拟 frps 管理接口不可用。
	failAll bool
	// onDelete 在每次收到关闭请求时被调用，用来断言「关代理时账号已经不在库里」。
	onDelete func(name string)
	// srv 是背后的 httptest 服务，install 时用它拼 FrpsClient。
	srv *httptest.Server
}

func newFakeFrpsProxies(t *testing.T, items ...string) *fakeFrpsProxies {
	t.Helper()
	f := &fakeFrpsProxies{items: items}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failAll {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.Method {
		case http.MethodGet:
			// total 必须如实等于条数：分页完整性只认 total，少报会被判成残缺响应。
			body := fmt.Sprintf(`{"total":%d,"page":1,"pageSize":200,"items":[%s]}`,
				len(f.items), strings.Join(f.items, ","))
			_, _ = w.Write([]byte(frpsOK(body)))
		case http.MethodDelete:
			name := r.URL.Query().Get("name")
			f.closed = append(f.closed, name)
			if f.onDelete != nil {
				f.onDelete(name)
			}
			_, _ = w.Write([]byte(frpsOK("null")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	f.srv = srv
	return f
}

// install 把这个假 frps 装到服务集合上。
func (f *fakeFrpsProxies) install(svc *Services) {
	svc.Frps = NewFrpsClient(&config.Config{
		FrpsAPIAddr:     f.srv.URL,
		FrpsAPIUser:     "admin",
		FrpsAPIPassword: "secret",
	})
}

func (f *fakeFrpsProxies) closedNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.closed))
	copy(out, f.closed)
	return out
}

// setFailAll / setOnDelete 在锁内改字段：假服务的 handler 跑在另一个 goroutine
// 里，直接赋值会被 -race 判成数据竞争。
func (f *fakeFrpsProxies) setFailAll(v bool) {
	f.mu.Lock()
	f.failAll = v
	f.mu.Unlock()
}

func (f *fakeFrpsProxies) setOnDelete(fn func(name string)) {
	f.mu.Lock()
	f.onDelete = fn
	f.mu.Unlock()
}

// proxyJSON 拼一条代理记录。clientID 传空即表示 frps 没有给出该字段。
func proxyJSON(name, clientID string, lastStartAt int64) string {
	var b strings.Builder
	b.WriteString(`{"name":` + strconv.Quote(name))
	if clientID != "" {
		b.WriteString(`,"clientID":` + strconv.Quote(clientID))
	}
	b.WriteString(fmt.Sprintf(`,"status":{"phase":"online","lastStartAt":%d}}`, lastStartAt))
	return b.String()
}

// newLifecycleUser 造一个启用状态的普通用户。
func newLifecycleUser(t *testing.T, svc *Services, name string) *model.User {
	t.Helper()
	hashed, err := auth.HashPassword("Passw0rd12345")
	if err != nil {
		t.Fatalf("生成密码失败: %v", err)
	}
	u := &model.User{Username: name, Password: hashed, Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	return u
}

// TestAdminDeleteUserClosesProxies 覆盖「管理员删号后代理还在跑」。
//
// 删号只清数据库与内存会话，拦得住新连接；已经在 frps 上转发的数据流不经过
// 任何准入判断，会一直跑到客户端自己退出。这里断言两件事：
//
//  1. 该用户名下的代理被逐个关闭；
//  2. 关闭动作发生在账号行**已经不存在**之后（事务已提交）。
//
// 第 2 点是修复核心：CloseUserProxies 原先靠 users.state_version 做跨实例
// 见证，账号删掉后那一行就没了，必须有一条「账号已删」的路径，否则删号
// 永远断不了流。
func TestAdminDeleteUserClosesProxies(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "delproxy")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t,
		proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past),
		proxyJSON(FrpUserOf(u.ID)+".nas", "client-b", past),
		// 别的账号的代理：绝对不能碰。
		proxyJSON(FrpUserOf(u.ID+10000)+".mc", "client-other", past),
	)
	f.install(svc)

	// 关代理时必须已经查不到账号：这就是「事务提交之后」的判据。
	f.setOnDelete(func(name string) {
		if name == FrpUserOf(u.ID+10000)+".mc" {
			t.Errorf("关闭了别的账号的代理 %q", name)
		}
		var n int64
		if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).Count(&n).Error; err != nil {
			t.Errorf("关闭代理 %q 时查账号失败: %v", name, err)
			return
		}
		if n != 0 {
			t.Errorf("关闭代理 %q 时账号仍在库里：断流必须在删除事务提交之后执行", name)
		}
	})

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("删除用户失败: %v", err)
	}

	got := f.closedNames()
	want := map[string]bool{
		FrpUserOf(u.ID) + ".mc":  true,
		FrpUserOf(u.ID) + ".nas": true,
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("关闭了不该关的代理 %q（完整列表 %v）", name, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("应关闭该账号的 2 条代理，实际 %v", got)
	}
}

// TestDeleteAccountClosesProxies 覆盖自助注销的同一缺陷。
//
// 两个删除路径必须给出同一种结果：用户主动「彻底删号」更不该留下还在转发的
// 隧道。这里同时验证账号行在关代理时已经不在了。
func TestDeleteAccountClosesProxies(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "selfproxy")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past))
	f.install(svc)

	f.setOnDelete(func(name string) {
		var n int64
		if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).Count(&n).Error; err != nil {
			t.Errorf("关闭代理 %q 时查账号失败: %v", name, err)
			return
		}
		if n != 0 {
			t.Errorf("关闭代理 %q 时账号仍在库里：注销的断流必须在事务提交之后", name)
		}
	})

	if err := svc.DeleteAccount(u.ID, "Passw0rd12345"); err != nil {
		t.Fatalf("注销失败: %v", err)
	}
	if got := f.closedNames(); len(got) != 1 || got[0] != FrpUserOf(u.ID)+".mc" {
		t.Fatalf("注销后应关闭该账号的代理，实际 %v", got)
	}
}

// TestAdminDeleteUserSucceedsWhenFrpsUnavailable 覆盖「frps 不可用不得让删除失败」。
//
// 账号必须删掉。管理端若收到错误去重试，只会得到「用户不存在」；而残留的代理
// 已经无法再建立新连接（插件找不到账号），靠日志留痕由运维排查。
func TestAdminDeleteUserSucceedsWhenFrpsUnavailable(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "delnoful")

	f := newFakeFrpsProxies(t, proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", time.Now().Unix()))
	f.setFailAll(true)
	f.install(svc)

	if err := svc.AdminDeleteUser(u.ID); err != nil {
		t.Fatalf("frps 不可用时删除仍必须成功，实际 %v", err)
	}
	var n int64
	if err := svc.DB.Model(&model.User{}).Where("id = ?", u.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("账号必须已经删掉")
	}
	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("frps 不可用时不该发出关闭请求，实际 %v", got)
	}
}

// TestCloseDeletedUserProxiesWithoutStateVersion 覆盖「账号行已不存在」的断流路径。
//
// 这是问题 1 的核心：CloseUserProxies 需要 users.state_version 做跨实例见证，
// 而删号之后那一行没了。CloseDeletedUserProxies 如实退化成「按前缀 + 代理实例
// 身份尽力关闭」，不查版本、不因账号缺失而放弃。
func TestCloseDeletedUserProxiesWithoutStateVersion(t *testing.T) {
	svc := newTestServices(t, nil)
	// 不建用户：模拟「删除事务已经提交」。
	const userID = 4242
	if _, err := svc.userStateVersionFromDB(userID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("前置条件：账号应不存在，实际 err=%v", err)
	}

	f := newFakeFrpsProxies(t,
		proxyJSON(FrpUserOf(userID)+".mc", "client-a", time.Now().Add(-time.Minute).Unix()),
		proxyJSON(FrpUserOf(userID+1)+".mc", "client-b", time.Now().Add(-time.Minute).Unix()),
	)
	f.install(svc)

	svc.CloseDeletedUserProxies(context.Background(), userID)

	if got := f.closedNames(); len(got) != 1 || got[0] != FrpUserOf(userID)+".mc" {
		t.Fatalf("账号已删时仍应按前缀关闭其代理，实际 %v", got)
	}
}

// TestAdminSetUserStatusRevokesDBSessionsInTx 覆盖「跨实例禁用仍能建新连接」。
//
// 另一台实例的插件回调走 onNewUserConn → EnsureSessionOnline →
// FindTrustedClientSession，读的是数据库里的会话行。状态事务里不把 online
// 置 false 的话，那台实例会一直看到「在线且未过期」的会话，继续放行新连接——
// 账号明明已禁用，数据连接却照建不误。
//
// 这里直接用 FindTrustedClientSession 断言「别的实例会看到什么」：插件在内存
// 未命中时的唯一回落依据就是它，查不到即拒绝。
func TestAdminSetUserStatusRevokesDBSessionsInTx(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "crossdisable")

	const runID = "run-cross"
	if err := svc.DB.Create(&model.ClientSession{
		UserID: u.ID, Username: u.Username, RunID: runID,
		Online: true, LastSeenAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("建客户端会话失败: %v", err)
	}
	if _, err := svc.FindTrustedClientSession(runID); err != nil {
		t.Fatalf("前置条件：会话应可信，实际 %v", err)
	}

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	if _, err := svc.FindTrustedClientSession(runID); err == nil {
		t.Fatal("禁用后数据库会话必须置为离线，否则其他实例仍会放行新连接")
	}
	var sess model.ClientSession
	if err := svc.DB.Where("run_id = ?", runID).First(&sess).Error; err != nil {
		t.Fatal(err)
	}
	if sess.Online {
		t.Fatal("库里 online 应为 false")
	}

	// 重新启用不得把已撤销的会话「复活」：重新上线只能通过重新登录
	// （Login / 凭据复核），否则撤销就形同虚设。
	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if _, err := svc.FindTrustedClientSession(runID); err == nil {
		t.Fatal("启用账号不该让已撤销的会话重新变为可信")
	}
}

// TestAdminSetUserStatusRollsBackWhenSessionRevokeFails 覆盖「撤销必须在事务内」。
//
// 把会话表删掉让 revoke 必然失败：若撤销在事务之外做，状态更新已经提交、
// 接口却报错——库里就是「已禁用但会话仍在线」，两个事实互相矛盾。
// 放进事务里，整笔变更一起回滚，管理员看到错误时数据库没有被改动过。
func TestAdminSetUserStatusRollsBackWhenSessionRevokeFails(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "revokefail")

	if err := svc.DB.Migrator().DropTable(&model.ClientSession{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusDisabled); err == nil {
		t.Fatal("会话撤销失败时必须如实报错，不能报告禁用成功")
	}

	var got model.User
	if err := svc.DB.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != model.UserStatusActive {
		t.Fatalf("撤销失败时状态变更必须一起回滚，实际 status=%q", got.Status)
	}
}

// TestCloseUserProxiesSkipsProxyWithoutIdentity 覆盖「双空身份退化成按名字关」。
//
// frps 没给 clientID、也没给 lastStartAt 时，这条记录没有任何可用于确认
// 「还是同一个代理实例」的字段。此时按名字关闭等于赌一把：客户端重连后会用
// 同一个名字重新注册，赌错就是把刚恢复的用户随机踢下线。
//
// 断言：双空的代理跳过；同一轮里带身份的代理照常关闭——跳过一条不能连累其余。
func TestCloseUserProxiesSkipsProxyWithoutIdentity(t *testing.T) {
	svc := newTestServices(t, nil)
	const userID = 77
	past := time.Now().Add(-time.Minute).Unix()

	f := newFakeFrpsProxies(t,
		// clientID 与 lastStartAt 都缺失：身份不可判定。
		`{"name":`+strconv.Quote(FrpUserOf(userID)+".noid")+`,"status":{"phase":"online"}}`,
		proxyJSON(FrpUserOf(userID)+".identified", "client-a", past),
	)
	f.install(svc)

	gen := svc.bumpUserStatusGen(userID)
	svc.CloseUserProxies(context.Background(), userID, gen, time.Now())

	got := f.closedNames()
	if len(got) != 1 || got[0] != FrpUserOf(userID)+".identified" {
		t.Fatalf("无身份代理必须跳过、有身份代理必须关闭，实际关闭了 %v", got)
	}
}

// TestCloseUserProxiesClosesProxyWithOnlyClientID 覆盖另一半判据。
//
// 双空才跳过；只有 clientID、没有 lastStartAt 时仍要按 clientID 比对后关闭，
// 否则老版本 frps（不返回 lastStartAt）就完全断不了流。
func TestCloseUserProxiesClosesProxyWithOnlyClientID(t *testing.T) {
	svc := newTestServices(t, nil)
	const userID = 78
	f := newFakeFrpsProxies(t,
		`{"name":`+strconv.Quote(FrpUserOf(userID)+".cli")+`,"clientID":"client-a","status":{"phase":"online"}}`,
	)
	f.install(svc)

	gen := svc.bumpUserStatusGen(userID)
	svc.CloseUserProxies(context.Background(), userID, gen, time.Now())

	if got := f.closedNames(); len(got) != 1 || got[0] != FrpUserOf(userID)+".cli" {
		t.Fatalf("只有 clientID 时仍应关闭，实际 %v", got)
	}
}
