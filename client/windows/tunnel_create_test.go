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

// TestCreateTunnelRefreshFailureIsNotCreateFailure 覆盖「创建成功、刷新失败」。
//
// POST 已经成功，隧道在服务端建好了。若把随后的刷新错误当成创建失败返回，
// 用户会重试一次，遇到「名称已存在」；批量创建早已是「创建成功、刷新错误
// 单独呈现」的语义，单条创建必须一致。
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
		// 其余请求（刷新所用的 /client/info）一律失败：模拟建完之后网络断了。
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
	// 刷新错误通过 SyncErr 呈现，用户仍能看到原因。
	if state.SyncErr == "" {
		t.Fatal("刷新失败应体现在 SyncErr 上，而不是被静默吞掉")
	}
}

// TestCreateTunnelHoldsSyncMuThroughRequest 覆盖「创建隧道期间全程持 syncMu」。
//
// 读凭据 → 发创建请求 → 对账必须是一个不被退出登录/重新接入打断的整体，
// 否则凭据可能在读到之后、发出之前被清空或切换，隧道会被建到旧账号上。
// 这里在服务端收到 POST 的那一刻检查客户端是否仍持有 syncMu。
func TestCreateTunnelHoldsSyncMuThroughRequest(t *testing.T) {
	withTempConfigDir(t)

	var app *App
	var postSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/user/tunnels") {
			postSeen.Store(true)
			if app == nil {
				t.Error("发出创建请求前应用对象应已就绪")
			} else if app.syncMu.TryLock() {
				app.syncMu.Unlock()
				t.Error("创建隧道发出请求期间 syncMu 应被持有")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"id":1}}`))
			return
		}
		// 对账所用的 /client/info 返回空清单即可。
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

// pagedVersionPanel 起一个列表版本逐页变化的假面板：
// 第 1 页版本 A，之后版本 B（模拟分页期间「删一条 + 增一条」）。
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

// TestFetchClientInfoDetectsVersionChange 覆盖「跨页版本变化」。
//
// 分页期间删掉一条已取到的、同时新增一条 id 更大的：总数不变，
// 新隧道落在游标之前永远取不到。只比条数发现不了，必须靠清单版本。
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
