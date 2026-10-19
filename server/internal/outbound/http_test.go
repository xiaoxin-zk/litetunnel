package outbound

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateHTTPURL(t *testing.T) {
	good := []string{
		"https://hooks.example.com/services/T000/B000/XXXX",
		"http://127.0.0.1:2586/mytopic",
		"https://192.168.1.10/notify",
		"https://example.com:8443/hook",
	}
	for _, raw := range good {
		if _, err := ValidateHTTPURL(raw); err != nil {
			t.Errorf("%s 应被接受，实际报错: %v", raw, err)
		}
	}

	bad := []struct {
		raw string
		why string
	}{
		{"", "空地址"},
		{"ftp://example.com/hook", "非 http(s) 协议"},
		{"https://user:pass@example.com/hook", "带用户信息"},
		{"http://169.254.169.254/latest/meta-data/", "AWS 元数据"},
		{"http://metadata.google.internal/computeMetadata/v1/", "GCP 元数据"},
		{"http://100.100.100.200/latest/meta-data/", "阿里云元数据"},
		{"http://[fd00:ec2::254]/latest/meta-data/", "AWS IPv6 元数据"},
		{"https://example.com:70000/x", "端口越界"},
		{"https://example.com/" + strings.Repeat("a", 600), "地址过长"},
	}
	for _, tc := range bad {
		if _, err := ValidateHTTPURL(tc.raw); err == nil {
			t.Errorf("%s（%s）必须被拒绝", tc.raw, tc.why)
		}
	}
}

func TestBlockedIPPolicy(t *testing.T) {
	allowed := []string{"127.0.0.1", "::1", "192.168.1.10", "10.0.0.5", "8.8.8.8"}
	for _, raw := range allowed {
		if blockedIP(netip.MustParseAddr(raw)) {
			t.Errorf("%s 是合法的自建接收端地址，不应被拒绝", raw)
		}
	}

	blocked := []string{
		"0.0.0.0",
		"169.254.169.254",
		"fe80::1",
		"224.0.0.1",
		"100.100.100.200",
		"fd00:ec2::254",
	}
	for _, raw := range blocked {
		if !blockedIP(netip.MustParseAddr(raw)) {
			t.Errorf("%s 必须被出站策略拒绝", raw)
		}
	}
}

// 字面量地址在建连前就该被拒，不能真的去连元数据服务。
func TestClientRejectsMetadataTarget(t *testing.T) {
	if _, err := Client().Get("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("指向云元数据的请求必须失败")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	resp, err := Client().Get(redirector.URL)
	if err != nil {
		t.Fatalf("请求本身不该报错（3xx 应作为响应返回）: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("应拿到原始 302，实际 %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("不能跟随重定向，实际打到了目标 %d 次", got)
	}
}

func TestSanitizeErrorDropsURL(t *testing.T) {
	raw := &url.Error{
		Op:  "Post",
		URL: "https://hooks.example.com/services/AAA/BBB/secret-token",
		Err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
	}
	got := SanitizeError(raw).Error()
	if strings.Contains(got, "secret-token") || strings.Contains(got, "/services/") {
		t.Fatalf("错误信息不能带出完整 URL（里面是凭据）: %s", got)
	}
	if !strings.Contains(got, "hooks.example.com") {
		t.Fatalf("至少应保留主机名，便于排查: %s", got)
	}

	plain := errors.New("接收端返回 HTTP 500")
	if SanitizeError(plain) != plain {
		t.Error("普通错误应原样返回")
	}
	if SanitizeError(nil) != nil {
		t.Error("nil 应保持 nil")
	}
}
