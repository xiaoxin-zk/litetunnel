package service

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

type fakeFrpsProxies struct {
	mu       sync.Mutex
	items    []string
	closed   []string
	lists    int
	failAll  bool
	onDelete func(name string)
	srv      *httptest.Server
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
			f.lists++
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

func (f *fakeFrpsProxies) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

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

func (f *fakeFrpsProxies) setItems(items ...string) {
	f.mu.Lock()
	f.items = items
	f.mu.Unlock()
}

func proxyJSON(name, clientID string, lastStartAt int64) string {
	var b strings.Builder
	b.WriteString(`{"name":` + strconv.Quote(name))
	if clientID != "" {
		b.WriteString(`,"clientID":` + strconv.Quote(clientID))
	}
	b.WriteString(fmt.Sprintf(`,"status":{"phase":"online","lastStartAt":%d}}`, lastStartAt))
	return b.String()
}

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

func TestAdminDeleteUserClosesProxies(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "delproxy")

	past := time.Now().Add(-time.Minute).Unix()
	f := newFakeFrpsProxies(t,
		proxyJSON(FrpUserOf(u.ID)+".mc", "client-a", past),
		proxyJSON(FrpUserOf(u.ID)+".nas", "client-b", past),
		proxyJSON(FrpUserOf(u.ID+10000)+".mc", "client-other", past),
	)
	f.install(svc)

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

func TestCloseDeletedUserProxiesWithoutStateVersion(t *testing.T) {
	svc := newTestServices(t, nil)
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

	if err := svc.AdminSetUserStatus(u.ID, model.UserStatusActive); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if _, err := svc.FindTrustedClientSession(runID); err == nil {
		t.Fatal("启用账号不该让已撤销的会话重新变为可信")
	}
}

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

func TestCloseUserProxiesSkipsProxyWithoutIdentity(t *testing.T) {
	svc := newTestServices(t, nil)
	const userID = 77
	past := time.Now().Add(-time.Minute).Unix()

	f := newFakeFrpsProxies(t,
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
