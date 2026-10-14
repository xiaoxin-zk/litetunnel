package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// FrpsClient 封装 frps 内置管理 API。
//
// 该接口只监听 127.0.0.1，用 basic auth 保护，仅控制面可访问。
type FrpsClient struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
}

// NewFrpsClient 构造 frps 管理接口客户端。
func NewFrpsClient(cfg *config.Config) *FrpsClient {
	addr := strings.TrimSpace(cfg.FrpsAPIAddr)
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return &FrpsClient{
		baseURL:  strings.TrimRight(addr, "/"),
		user:     cfg.FrpsAPIUser,
		password: cfg.FrpsAPIPassword,
		http: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// FrpsProxyStatus 代理运行态。
type FrpsProxyStatus struct {
	Phase           string `json:"phase"`
	TodayTrafficIn  int64  `json:"todayTrafficIn"`
	TodayTrafficOut int64  `json:"todayTrafficOut"`
	CurConns        int64  `json:"curConns"`
	LastStartAt     int64  `json:"lastStartAt"`
	LastCloseAt     int64  `json:"lastCloseAt"`
}

// FrpsProxy frps 侧的一条代理记录。
type FrpsProxy struct {
	Name     string          `json:"name"`
	User     string          `json:"user"`
	ClientID string          `json:"clientID"`
	Status   FrpsProxyStatus `json:"status"`
}

type frpsPage[T any] struct {
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Items    []T `json:"items"`
}

// ListProxies 拉取全部代理。分页抓取，避免代理数量增长后被截断。
func (c *FrpsClient) ListProxies(ctx context.Context) ([]FrpsProxy, error) {
	const pageSize = 200
	var all []FrpsProxy
	for page := 1; page <= 50; page++ {
		endpoint := fmt.Sprintf("%s/api/v2/proxies?page=%d&pageSize=%d", c.baseURL, page, pageSize)
		var out frpsPage[FrpsProxy]
		if err := c.getJSON(ctx, endpoint, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Items...)
		if len(out.Items) < pageSize || len(all) >= out.Total {
			break
		}
	}
	return all, nil
}

func (c *FrpsClient) getJSON(ctx context.Context, endpoint string, out any) error {
	if _, err := url.Parse(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("请求 frps 管理接口失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("frps 管理接口返回状态码 %d", resp.StatusCode)
	}
	// 限制响应体大小，防止异常响应耗尽内存。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// ParseProxyName 拆分 frp 代理名。
//
// frpc 配置了 user = "lt_<username>"，frp 会把代理名规范为 "<user>.<proxy_name>"，
// 且用户名被限制为 [A-Za-z0-9_]，因此第一个 "." 即分隔符。
func ParseProxyName(name string) (frpUser, proxyName string, ok bool) {
	idx := strings.Index(name, ".")
	if idx <= 0 || idx == len(name)-1 {
		return "", "", false
	}
	return name[:idx], name[idx+1:], true
}

// UsernameFromFrpUser 从 frp 的 user 字段还原平台用户名。
func UsernameFromFrpUser(frpUser string) (string, bool) {
	if !strings.HasPrefix(frpUser, ProxyNamePrefix) {
		return "", false
	}
	name := strings.TrimPrefix(frpUser, ProxyNamePrefix)
	if name == "" {
		return "", false
	}
	return name, true
}
