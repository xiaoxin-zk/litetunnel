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
	// invalid 记录「地址语法不合法」的原因。这种配置下一个请求都不能发：
	// 请求会带上 Bearer token，随后还有渲染下发的配置凭据。
	invalid string
}

// NewClient 构造客户端。base 形如 http://127.0.0.1:7850。
//
// 地址必须先过 ParseBaseURL：旧实现只判断「以 http 开头」，而那根本不是
// 边界——`http://127.0.0.1:7850@evil.example.com` 由 net/http 解析出的
// 主机是 evil.example.com，于是 token 与配置凭据被发到了完全无关的地址。
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

// ParseBaseURL 严格解析 helper 地址，返回规范化结果（scheme://host[:port]）。
//
// 只接受 http/https、必须带主机、不允许用户信息/路径/查询参数/片段。
// 这些限制不针对正常写法，而是为了让「字符串看起来像本机地址」和
// 「请求实际发往哪里」不可能分叉。
//
// 是否允许非回环地址仍然交给运维决定：面板跑在容器里时，helper 常常是
// 宿主机的桥接地址（172.17.0.1、host.docker.internal），一律禁止回环
// 之外的地址会让这种部署直接不可用。
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

// Configured 表示面板侧是否配齐了地址与令牌。
func (c *Client) Configured() bool { return c.base != "" && c.token != "" }

// Health 探测 helper。
func (c *Client) Health() (Health, error) {
	var out Health
	if err := c.do(context.Background(), http.MethodGet, "/health", nil, &out, healthTimeout); err != nil {
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
	if err := c.do(context.Background(), http.MethodPost, "/render", req, &out, renderTimeout); err != nil {
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
	if err := c.do(context.Background(), http.MethodPost, "/apply", nil, &out, renderTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// DNSCheck 解析域名并返回结果。
//
// ctx 来自发起这次检查的 HTTP 请求：DNS 检查是串行查若干条记录，全部超时
// 时能堆到近两分钟，而管理员很可能早就关掉页面或点了别的菜单。不把请求
// 的取消传下去，这些查询会照常跑完，重复点击就叠成一堆后台任务。
func (c *Client) DNSCheck(ctx context.Context, req DNSCheckRequest) ([]DNSRecord, error) {
	var out struct {
		Records []DNSRecord `json:"records"`
	}
	if err := c.do(ctx, http.MethodPost, "/dns/check", req, &out, queryTimeout); err != nil {
		return nil, err
	}
	return out.Records, nil
}

// Certs 读取 Caddy 证书存储里的证书。
func (c *Client) Certs() (CertStatus, error) {
	var out CertStatus
	if err := c.do(context.Background(), http.MethodGet, "/certs", nil, &out, queryTimeout); err != nil {
		return out, err
	}
	return out, nil
}

// Reason 返回不可用的原因，供界面直接展示。
func (c *Client) Reason() string {
	if c.invalid != "" {
		// 地址写坏时不发请求，直接把原因说出来：这时候任何一次调用都会
		// 把 token 发到一个由 URL 解析器挑出来的主机上。
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
