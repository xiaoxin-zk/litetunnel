package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreateTunnelRefreshFailureIsNotCreateFailure(t *testing.T) {
	withTempConfigDir(t)

	var posted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/user/tunnels") {
			posted.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"id":1}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	state, err := a.CreateTunnel("mc", "tcp", "127.0.0.1", 25565, 0, "")
	if err != nil {
		t.Fatalf("创建成功后刷新失败不应报创建失败: %v", err)
	}
	if !posted.Load() {
		t.Fatal("应当发出创建请求")
	}
	if state.SyncErr == "" {
		t.Fatal("刷新失败应体现在 SyncErr 上，而不是被静默吞掉")
	}
}

func TestCreateTunnelHoldsSyncMuThroughRequest(t *testing.T) {
	withTempConfigDir(t)

	var app *App
	var postSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/user/tunnels") {
			postSeen.Store(true)
			if app == nil {
				t.Error("发出创建请求前应用对象应已就绪")
			} else if !syncGateHeld(app) {
				t.Error("创建隧道发出请求期间 syncMu 应被持有")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"id":1}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"username":"u","tunnels":[]}}`))
	}))
	t.Cleanup(srv.Close)

	a := newSyncTestApp(t, srv)
	app = a

	if _, err := a.CreateTunnel("mc", "tcp", "127.0.0.1", 25565, 0, ""); err != nil {
		t.Fatalf("创建隧道失败: %v", err)
	}
	if !postSeen.Load() {
		t.Fatal("应当发出创建请求")
	}
}

func pagedVersionPanel(t *testing.T, n int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beforeID := r.URL.Query().Get("before_id")
		limit := 2
		if v := r.URL.Query().Get("limit"); v != "" {
			_, _ = fmt.Sscanf(v, "%d", &limit)
		}
		version := "v1"
		if beforeID != "" {
			version = "v2"
		}
		ids := make([]int, 0, limit)
		end := n
		if beforeID != "" {
			_, _ = fmt.Sscanf(beforeID, "%d", &end)
		}
		for id := end; id >= 1 && len(ids) < limit; id-- {
			if beforeID != "" && id >= end {
				continue
			}
			ids = append(ids, id)
		}
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"code":0,"message":"ok","data":{"username":"u","tunnel_total":%d,"list_version":"%s","tunnels":[`, n, version)
		for i, id := range ids {
			if i > 0 {
				body += ","
			}
			body += fmt.Sprintf(`{"id":%d,"name":"t%d","type":"tcp","status":"active"}`, id, id)
		}
		body += `]}}`
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchClientInfoDetectsVersionChange(t *testing.T) {
	oldSize := clientInfoPageSize
	clientInfoPageSize = 2
	t.Cleanup(func() { clientInfoPageSize = oldSize })

	srv := pagedVersionPanel(t, 4)
	a := newSyncTestApp(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := a.fetchClientInfo(ctx, srv.URL, "k")
	if err == nil {
		t.Fatal("分页期间清单版本变化时必须报错，不能拿可能漏项的清单去对账")
	}
	if !strings.Contains(err.Error(), "列表版本") {
		t.Fatalf("错误应说明版本变化，实际 %v", err)
	}
}
