package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

type FrpsClient struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
}

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

type FrpsProxyStatus struct {
	Phase           string `json:"phase"`
	TodayTrafficIn  int64  `json:"todayTrafficIn"`
	TodayTrafficOut int64  `json:"todayTrafficOut"`
	CurConns        int64  `json:"curConns"`
	LastStartAt     int64  `json:"lastStartAt"`
	LastCloseAt     int64  `json:"lastCloseAt"`
}

type FrpsProxy struct {
	Name     string          `json:"name"`
	User     string          `json:"user"`
	ClientID string          `json:"clientID"`
	Status   FrpsProxyStatus `json:"status"`
}

type frpsPage[T any] struct {
	Total    *int `json:"total"`
	Page     int  `json:"page"`
	PageSize int  `json:"pageSize"`
	Items    []T  `json:"items"`
}

const frpsSuccessCode = 200

type frpsEnvelope struct {
	Code *int            `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (c *FrpsClient) ListProxies(ctx context.Context) ([]FrpsProxy, error) {
	var lastErr error
	for attempt := 1; attempt <= frpsListAttempts; attempt++ {
		list, err := c.listProxiesOnce(ctx)
		if err == nil {
			return list, nil
		}
		lastErr = err
		if !errors.Is(err, errFrpsListUnstable) {
			return nil, err
		}
	}
	return nil, lastErr
}

var errFrpsListUnstable = errors.New("frps 代理列表在分页期间发生变化")

const (
	frpsPageSize     = 200
	frpsMaxPages     = 500
	frpsListAttempts = 2
)

func (c *FrpsClient) listProxiesOnce(ctx context.Context) ([]FrpsProxy, error) {
	var all []FrpsProxy
	seen := make(map[string]struct{}, 256)
	total := -1
	var firstPageNames []string
	pagesRead := 0

	for page := 1; page <= frpsMaxPages; page++ {
		endpoint := fmt.Sprintf("%s/api/v2/proxies?page=%d&pageSize=%d", c.baseURL, page, frpsPageSize)
		var out frpsPage[FrpsProxy]
		if err := c.getJSON(ctx, endpoint, &out); err != nil {
			return nil, err
		}
		pagesRead++

		if out.Total == nil {
			return nil, fmt.Errorf("frps 代理列表缺少 total 字段（第 %d 页），无法确认完整性", page)
		}

		if total < 0 {
			total = *out.Total
			if total > frpsMaxPages*frpsPageSize {
				return nil, fmt.Errorf("frps 报告代理数 %d 条，超过采集上限 %d 条",
					total, frpsMaxPages*frpsPageSize)
			}
		} else if *out.Total != total {
			return nil, fmt.Errorf("%w：第 %d 页 total=%d，第 1 页是 %d",
				errFrpsListUnstable, page, *out.Total, total)
		}

		for _, p := range out.Items {
			if _, dup := seen[p.Name]; dup {
				return nil, fmt.Errorf("%w：代理 %q 重复出现（重复会让同一段流量被计两次）",
					errFrpsListUnstable, p.Name)
			}
			seen[p.Name] = struct{}{}
			all = append(all, p)
			if page == 1 {
				firstPageNames = append(firstPageNames, p.Name)
			}
		}

		if total > 0 && len(all) >= total {
			if len(all) > total {
				return nil, fmt.Errorf("%w：已取 %d 条，超过上报的 total=%d",
					errFrpsListUnstable, len(all), total)
			}
			if pagesRead > 1 {
				if err := c.recheckFirstPage(ctx, total, firstPageNames); err != nil {
					return nil, err
				}
			}
			return all, nil
		}

		if len(out.Items) < frpsPageSize {
			if total == 0 && len(out.Items) == 0 && page == 1 {
				return all, nil
			}
			return nil, fmt.Errorf(
				"frps 代理列表不完整：已取 %d 条，上报 total=%d，第 %d 页仅返回 %d 条（每页 %d）",
				len(all), total, page, len(out.Items), frpsPageSize)
		}
	}
	return nil, fmt.Errorf("frps 代理数超过分页上限（%d 页 × %d 条），拒绝返回不完整列表",
		frpsMaxPages, frpsPageSize)
}

func (c *FrpsClient) recheckFirstPage(ctx context.Context, wantTotal int, first []string) error {
	endpoint := fmt.Sprintf("%s/api/v2/proxies?page=1&pageSize=%d", c.baseURL, frpsPageSize)
	var out frpsPage[FrpsProxy]
	if err := c.getJSON(ctx, endpoint, &out); err != nil {
		return err
	}
	if out.Total == nil {
		return fmt.Errorf("frps 代理列表缺少 total 字段（复核第 1 页），无法确认完整性")
	}
	if *out.Total != wantTotal {
		return fmt.Errorf("%w：复核第 1 页时 total=%d，本轮开始是 %d",
			errFrpsListUnstable, *out.Total, wantTotal)
	}
	if len(out.Items) != len(first) {
		return fmt.Errorf("%w：复核第 1 页拿到 %d 条，本轮开始时是 %d 条",
			errFrpsListUnstable, len(out.Items), len(first))
	}
	for i, p := range out.Items {
		if p.Name != first[i] {
			return fmt.Errorf("%w：复核第 1 页第 %d 条是 %q，本轮开始时是 %q（总量没变但集合变了）",
				errFrpsListUnstable, i+1, p.Name, first[i])
		}
	}
	return nil
}

func (c *FrpsClient) doJSON(ctx context.Context, method, endpoint string, out any, allowEmptyData bool) error {
	if _, err := url.Parse(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}

	var env frpsEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("frps 管理接口响应不是合法 JSON: %w", err)
	}
	if env.Code == nil {
		return errors.New("frps 管理接口响应缺少 code 字段")
	}
	if *env.Code != frpsSuccessCode {
		msg := strings.TrimSpace(env.Msg)
		if msg == "" {
			msg = "未提供原因"
		}
		return fmt.Errorf("frps 管理接口返回非成功码 %d: %s", *env.Code, msg)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		if allowEmptyData {
			return nil
		}
		return errors.New("frps 管理接口响应缺少 data 字段")
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("解析 frps 管理接口 data 失败: %w", err)
	}
	return nil
}

func (c *FrpsClient) getJSON(ctx context.Context, endpoint string, out any) error {
	return c.doJSON(ctx, http.MethodGet, endpoint, out, false)
}

func (c *FrpsClient) CloseProxy(ctx context.Context, name string) error {
	endpoint := fmt.Sprintf("%s/api/proxies?name=%s", c.baseURL, url.QueryEscape(name))
	return c.doJSON(ctx, http.MethodDelete, endpoint, nil, true)
}

func ParseProxyName(name string) (frpUser, proxyName string, ok bool) {
	idx := strings.Index(name, ".")
	if idx <= 0 || idx == len(name)-1 {
		return "", "", false
	}
	return name[:idx], name[idx+1:], true
}

var proxyPhaseOnline = map[string]bool{
	"online":  true,
	"running": true,
}

func IsProxyOnline(phase string) bool {
	return proxyPhaseOnline[strings.ToLower(strings.TrimSpace(phase))]
}
