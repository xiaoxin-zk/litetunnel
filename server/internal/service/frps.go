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
// frpc 配置了 user = "lt_u<用户ID>"，frp 会把代理名规范为 "<user>.<proxy_name>"。
// 第一个 "." 即分隔符：用户名被限制为 [A-Za-z0-9_]，而隧道名由
// IsSafeName 限制为字母/数字/下划线且不允许以 "lt" 开头，
// 因此两边都不可能出现 "."，不存在歧义。
func ParseProxyName(name string) (frpUser, proxyName string, ok bool) {
	idx := strings.Index(name, ".")
	if idx <= 0 || idx == len(name)-1 {
		return "", "", false
	}
	return name[:idx], name[idx+1:], true
}

// 说明：从 frp user 字段还原身份的解析逻辑已迁移到 frpc.go 的 UserIDFromFrpUser。
// 早期版本用「用户名」作前缀，导致用户改名会破坏全部已下发配置，现已改为不可变用户 ID。

// proxyPhaseOnline 是 frps 管理接口用来表示「代理已注册并监听」的 phase 取值。
//
// 必须同时认多个：frps 不同版本给的字符串不一样——较早的版本用 "running"，
// v0.71 的管理接口返回的是 "online"。
//
// 只认其中一个的后果很隐蔽：代理其实已经注册成功、端口也已经在监听，
// 但面板把它算成离线，客户端据此一直显示「连接中」，用户反复重启客户端、
// 检查防火墙都无效。这个错误真实发生过。
var proxyPhaseOnline = map[string]bool{
	"online":  true,
	"running": true,
}

// IsProxyOnline 判断 frps 返回的代理 phase 是否表示代理在线。
//
// 大小写与空白都容忍：这是外部系统给的字符串，不该因为一个空格
// 就把整条隧道判成离线。
func IsProxyOnline(phase string) bool {
	return proxyPhaseOnline[strings.ToLower(strings.TrimSpace(phase))]
}
