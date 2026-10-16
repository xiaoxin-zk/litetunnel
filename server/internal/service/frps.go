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

// frpsEnvelope 是 frps 管理 API 的统一响应包装。
//
// frps v0.71 的所有管理接口都返回 {code, msg, data}，分页对象在 data 里：
//
//	{"code":0,"msg":"","data":{"total":1,"page":1,"pageSize":200,"items":[...]}}
//
// 这里必须显式解包。曾经是把整个响应体直接反序列化成 frpsPage：json 对
// 多余的字段是宽容的，**不会报错**，只是 Items 恒为空。采集器于是拿到一份
// 「空代理列表」，把所有隧道判成离线，客户端一直显示「连接中」，
// 而面板日志里没有任何异常。静默失败比报错难查得多。
type frpsEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// ListProxies 拉取全部代理。分页抓取，避免代理数量增长后被截断。
//
// 「返回错误」与「返回空列表」是两件完全不同的事，调用方必须区分：
//
//   - 返回错误：没拿到可信数据，应当保留上一次的在线状态；
//   - 返回空列表且无错误：frps 明确告诉我们当前没有任何代理，
//     此时把隧道判为离线才是对的。
//
// 任何格式不符都走第一条，绝不退化成空列表。
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

// getJSON 请求 frps 管理接口，解开 {code,msg,data} 后把 data 解到 out。
//
// 每一步不对都返回错误：状态码非 200、响应不是合法 JSON、业务错误码非 0、
// 缺少 data、data 解不出来。**绝不返回「零值 + nil」**——那等于告诉调用方
// 「代理列表是空的」，而真实情况是我们根本没读懂响应。
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

	var env frpsEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("frps 管理接口响应不是合法 JSON: %w", err)
	}
	// frps 用 code 表达业务错误，此时 HTTP 状态码仍然是 200。
	if env.Code != 0 {
		msg := strings.TrimSpace(env.Msg)
		if msg == "" {
			msg = "未提供原因"
		}
		return fmt.Errorf("frps 管理接口返回错误码 %d: %s", env.Code, msg)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return errors.New("frps 管理接口响应缺少 data 字段")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("解析 frps 管理接口 data 失败: %w", err)
	}
	return nil
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
