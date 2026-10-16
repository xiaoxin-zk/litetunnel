package tlscfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// healthTimeout 是探测 helper 是否在线的超时，必须短：
	// 它出现在「打开设置页」这条路径上，helper 没起时界面不该卡住。
	healthTimeout = 3 * time.Second
	// renderTimeout 覆盖「渲染 → 起容器校验 → 重建容器」，其中可能包含
	// 拉取 Caddy 镜像。给得宽松些，但要小于 HTTP 请求的整体超时。
	renderTimeout = 3 * time.Minute
	// queryTimeout 用于 DNS 检查与证书扫描这类只读操作。
	queryTimeout = 20 * time.Second
)

// Client 是宿主机 lt-config helper 的客户端。
//
// 与防火墙 helper（internal/firewall）同构：回环 HTTP + Bearer token，
// 不跟随重定向，错误原文回传——管理员需要知道「为什么没生效」。
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient 构造客户端。base 形如 http://127.0.0.1:7850。
func NewClient(base, token string) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base != "" && !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	return &Client{
		base:  base,
		token: token,
		http: &http.Client{
			Timeout: renderTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Configured 表示面板侧是否配齐了地址与令牌。
func (c *Client) Configured() bool { return c.base != "" && c.token != "" }

// Health 探测 helper。
func (c *Client) Health() (Health, error) {
	var out Health
	if err := c.do(http.MethodGet, "/health", nil, &out, healthTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// Available 判断 helper 是否可用（配置齐全且健康检查通过）。
func (c *Client) Available() bool {
	if !c.Configured() {
		return false
	}
	h, err := c.Health()
	return err == nil && h.Available
}

// Render 让 helper 渲染并（可选）应用配置。
func (c *Client) Render(req RenderRequest) (RenderResult, error) {
	var out RenderResult
	if err := c.do(http.MethodPost, "/render", req, &out, renderTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// Apply 只用当前已渲染好的文件重建容器。
//
// 单独留一个入口是为了「保存成功但重启失败」这种常见情形：
// 管理员修好宿主机问题后点一下重试即可，不必再走一遍渲染。
func (c *Client) Apply() (RenderResult, error) {
	var out RenderResult
	if err := c.do(http.MethodPost, "/apply", nil, &out, renderTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// DNSCheck 解析域名并返回结果。
func (c *Client) DNSCheck(req DNSCheckRequest) ([]DNSRecord, error) {
	var out struct {
		Records []DNSRecord `json:"records"`
	}
	if err := c.do(http.MethodPost, "/dns/check", req, &out, queryTimeout); err != nil {
		return nil, err
	}
	return out.Records, nil
}

// Certs 读取 Caddy 证书存储里的证书。
func (c *Client) Certs() (CertStatus, error) {
	var out CertStatus
	if err := c.do(http.MethodGet, "/certs", nil, &out, queryTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// Reason 返回不可用的原因，供界面直接展示。
func (c *Client) Reason() string {
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

func (c *Client) do(method, path string, body any, out any, timeout time.Duration) error {
	if !c.Configured() {
		return fmt.Errorf("宿主机配置服务未配置")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 每次调用单独设超时：渲染要几分钟，健康检查只要几秒。
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
