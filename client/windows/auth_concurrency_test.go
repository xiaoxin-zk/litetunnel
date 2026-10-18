package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogoutKeepsCredentialLockThroughCleanup(t *testing.T) {
	withTempConfigDir(t)
	panel, _, _, _ := fakePanel(t)
	a := newSyncTestApp(t, panel)
	for _, failMain := range []bool{false, true} {
		calls := 0
		cleanup := func() error {
			calls++
			if a.authMu.TryLock() {
				a.authMu.Unlock()
				t.Error("磁盘清理期间认证锁已释放")
			}
			if !syncGateHeld(a) {
				t.Error("磁盘清理期间同步锁已释放")
			}
			if calls == 1 && failMain {
				return errors.New("cleanup failed")
			}
			return nil
		}
		_, err := a.logout(cleanup, cleanup)
		if (err != nil) != failMain || calls != 2 {
			t.Fatalf("两项清理均须尝试: err=%v calls=%d", err, calls)
		}
		if !a.authMu.TryLock() {
			t.Fatal("退出返回后认证锁未释放")
		}
		a.authMu.Unlock()
	}
}

func TestConnectBeforeLogoutCannotPublishAfterRelogin(t *testing.T) {
	withTempConfigDir(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/client/config") {
			t.Error("过期接入不应请求隧道配置")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		select {
		case <-entered:
		default:
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"username":"old","tunnels":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"username":"new","tunnels":[]}}`))
	}))
	defer panel.Close()
	defer unblock()
	a := newSyncTestApp(t, panel)
	result := make(chan error, 1)
	go func() { _, err := a.Connect("test-key", panel.URL); result <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("接入请求未进入校验")
	}
	if _, err := a.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Connect("test-key", panel.URL); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("登出前开始的接入不应重新发布凭据")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("过期接入未结束")
	}
	a.mu.RLock()
	name := a.username
	a.mu.RUnlock()
	if name != "new" {
		t.Fatalf("旧请求覆盖了新登录: %q", name)
	}
	cfg, err := loadConfig()
	if err != nil || cfg.APIKey != "test-key" {
		t.Fatalf("新凭据应保留在磁盘: %+v %v", cfg, err)
	}
	if _, err := a.Logout(); err != nil {
		t.Fatal(err)
	}
	path, err := configFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("退出后配置仍存在: %v", err)
	}
}
