package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newHTTPTestApp() *App {
	return &App{http: &http.Client{Timeout: 5 * time.Second}}
}

// 401 必须被识别成「凭据失效」，否则账号被删后客户端不会退出登录。
func TestDoReportsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"账号已被禁用或不存在，请重新登录"}`))
	}))
	defer srv.Close()

	a := newHTTPTestApp()
	_, err := a.do(context.Background(), http.MethodGet, srv.URL, "some-key", nil)
	if err == nil {
		t.Fatal("401 应返回错误")
	}
	if !unauthorized(err) {
		t.Fatalf("401 应被识别为凭据失效，实际 %v", err)
	}
	// 还没接入（本地没有保存的凭据）时不能触发自动退出。
	if a.authRejected {
		t.Error("未登录时不该标记为凭据失效")
	}
}

// 403 可能是 IP 封禁、只读接口等业务限制，不能据此清掉本地凭据。
func TestDoKeepsForbiddenSeparate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":403,"message":"当前 IP 已被管理员封禁"}`))
	}))
	defer srv.Close()

	a := newHTTPTestApp()
	_, err := a.do(context.Background(), http.MethodGet, srv.URL, "some-key", nil)
	if err == nil {
		t.Fatal("403 应返回错误")
	}
	if unauthorized(err) {
		t.Error("403 不该被当成凭据失效")
	}
}

func TestDoKeepsServerErrorsSeparate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"message":"内部错误"}`))
	}))
	defer srv.Close()

	a := newHTTPTestApp()
	_, err := a.do(context.Background(), http.MethodGet, srv.URL, "some-key", nil)
	if err == nil {
		t.Fatal("500 应返回错误")
	}
	if unauthorized(err) {
		t.Error("5xx 不该被当成凭据失效")
	}
}

// 隧道配置走 getRawWithRev，同样要保留状态码。
func TestGetRawReportsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	a := newHTTPTestApp()
	_, _, err := a.getRawWithRev(context.Background(), srv.URL, "some-key")
	if err == nil {
		t.Fatal("401 应返回错误")
	}
	if !unauthorized(err) {
		t.Fatalf("401 应被识别为凭据失效，实际 %v", err)
	}
}
