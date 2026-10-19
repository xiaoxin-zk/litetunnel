package tlscfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	healthTimeout = 3 * time.Second
	renderTimeout = 3 * time.Minute
	queryTimeout  = 20 * time.Second
)

type Client struct {
	base    string
	token   string
	http    *http.Client
	invalid string
}

func NewClient(base, token string) *Client {
	c := &Client{
		token: token,
		http: &http.Client{
			Timeout: renderTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	normalized, err := ParseBaseURL(base)
	if err != nil {
		if strings.TrimSpace(base) != "" {
			c.invalid = fmt.Sprintf("配置服务地址不合法（%s）: %v", base, err)
		}
		return c
	}
	c.base = normalized
	return c
}

func ParseBaseURL(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", errors.New("地址为空")
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("无法解析: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("只支持 http/https，实际是 %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("缺少主机名或端口")
	}
	if u.User != nil {
		return "", errors.New("不允许包含用户信息（@ 之前的凭证部分）")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("不允许包含查询参数或片段")
	}
	if p := u.Path; p != "" && p != "/" {
		return "", fmt.Errorf("不允许包含路径（%q）", p)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("端口不合法（%q）", port)
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

func (c *Client) Configured() bool { return c.base != "" && c.token != "" }

func (c *Client) Health() (Health, error) {
	var out Health
	if err := c.do(context.Background(), http.MethodGet, "/health", nil, &out, healthTimeout); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) Available() bool {
	if !c.Configured() {
		return false
	}
	h, err := c.Health()
	return err == nil && h.Available
}

func (c *Client) Render(ctx context.Context, req RenderRequest) (RenderResult, error) {
	var out RenderResult
	if err := c.do(ctx, http.MethodPost, "/render", req, &out, renderTimeout); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) Apply(ctx context.Context) (RenderResult, error) {
	var out RenderResult
	if err := c.do(ctx, http.MethodPost, "/apply", nil, &out, renderTimeout); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) DNSCheck(ctx context.Context, req DNSCheckRequest) ([]DNSRecord, error) {
	var out struct {
		Records []DNSRecord `json:"records"`
	}
	if err := c.do(ctx, http.MethodPost, "/dns/check", req, &out, queryTimeout); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (c *Client) Certs() (CertStatus, error) {
	var out CertStatus
	if err := c.do(context.Background(), http.MethodGet, "/certs", nil, &out, queryTimeout); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) Reason() string {
	if c.invalid != "" {
		return c.invalid
	}
	if c.base == "" {
		return "未配置宿主机配置服务地址，请在「域名与证书」中填写"
	}
	if c.token == "" {
		return "未配置配置服务访问令牌，请在「域名与证书」中填写"
	}
	h, err := c.Health()
	if err != nil {
		return fmt.Sprintf("无法连接宿主机配置服务（%s），请确认 lt-config 已启动：%v", c.base, err)
	}
	if !h.Available {
		return h.Reason
	}
	return ""
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any, timeout time.Duration) error {
	if !c.Configured() {
		return fmt.Errorf("宿主机配置服务未配置")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := *c.http
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("连接宿主机配置服务失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("宿主机配置服务返回状态码 %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
