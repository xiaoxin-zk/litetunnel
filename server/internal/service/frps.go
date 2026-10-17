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

// frpsSuccessCode 是 frps v0.71 管理接口的成功码。
//
// 注意它**不是 0**：frps 用的是 HTTP 风格的状态码，实测成功响应是
//
//	{"code":200,"msg":"success","data":{...}}
//
// 这里曾经按 `code != 0` 判错，于是把每一个成功响应都当成业务错误：
// 采集器持续报错、保留旧状态，隧道永远显示不了在线。而当时的单元测试
// 用的是自己编的 `code:0`，全绿——fixture 与真实契约不一致时，
// 测试不但测不出问题，还会给出「已验证」的假象。
const frpsSuccessCode = 200

// frpsEnvelope 是 frps 管理 API 的统一响应包装。
//
// frps v0.71 的所有管理接口都返回 {code, msg, data}，分页对象在 data 里：
//
//	{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[...]}}
//
// 这里必须显式解包。曾经是把整个响应体直接反序列化成 frpsPage：json 对
// 多余的字段是宽容的，**不会报错**，只是 Items 恒为空。采集器于是拿到一份
// 「空代理列表」，把所有隧道判成离线，客户端一直显示「连接中」，
// 而面板日志里没有任何异常。静默失败比报错难查得多。
type frpsEnvelope struct {
	// Code 用指针，必须区分「字段缺失」与「值为 0」。
	//
	// 解成普通 int 时，缺字段会默认成 0；一旦 data 恰好合法就会被放行，
	// 而我们对这份响应其实一无所知。缺字段本身就是「读不懂」。
	Code *int            `json:"code"`
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
	var lastErr error
	for attempt := 1; attempt <= frpsListAttempts; attempt++ {
		list, err := c.listProxiesOnce(ctx)
		if err == nil {
			return list, nil
		}
		lastErr = err
		if !errors.Is(err, errFrpsListUnstable) {
			// 格式错误 / 网络错误：重试没有意义，直接返回。
			return nil, err
		}
	}
	return nil, lastErr
}

// errFrpsListUnstable 表示分页期间代理集合发生了变化（总数变了或出现重复项）。
//
// 这类结果既不能采信也不能「尽力去重」：总量变化说明翻页期间有代理增删，
// 重复项会让同一份流量在 runtime 里被累加两次。规则很简单——整轮重取一次，
// 仍不稳定就报错，让调用方保住上一轮的在线状态与采样基线。
var errFrpsListUnstable = errors.New("frps 代理列表在分页期间发生变化")

const (
	// frpsPageSize 是 frps 管理接口的单页条数。
	frpsPageSize = 200
	// frpsMaxPages 是绝对上限（200 × 500 = 10 万条）。
	//
	// 实际页数按第一页上报的 total 推算，所以几千、上万条都能完整取回；
	// 这个上限只用来挡住「对端报了一个荒谬的 total，让我们一直翻下去」。
	// 之前写死 50 页（1 万条），规模一过线采集就永久失败——而失败的表现是
	// 「在线状态停在旧值」，日志里只有一行拉取失败，很难联想到是上限。
	frpsMaxPages = 500
	// frpsListAttempts 是集合不稳定时的整轮重取次数。
	frpsListAttempts = 2
)

// listProxiesOnce 做一轮完整分页抓取，并校验各页之间的一致性。
func (c *FrpsClient) listProxiesOnce(ctx context.Context) ([]FrpsProxy, error) {
	var all []FrpsProxy
	seen := make(map[string]struct{}, 256)
	total := -1

	for page := 1; page <= frpsMaxPages; page++ {
		endpoint := fmt.Sprintf("%s/api/v2/proxies?page=%d&pageSize=%d", c.baseURL, page, frpsPageSize)
		var out frpsPage[FrpsProxy]
		if err := c.getJSON(ctx, endpoint, &out); err != nil {
			return nil, err
		}

		if total < 0 {
			total = out.Total
			// 提前判上限：total 明摆着超出能力时，不必真翻满 500 页再报错。
			if total > frpsMaxPages*frpsPageSize {
				return nil, fmt.Errorf("frps 报告代理数 %d 条，超过采集上限 %d 条",
					total, frpsMaxPages*frpsPageSize)
			}
		} else if out.Total != total {
			return nil, fmt.Errorf("%w：第 %d 页 total=%d，第 1 页是 %d",
				errFrpsListUnstable, page, out.Total, total)
		}

		for _, p := range out.Items {
			if _, dup := seen[p.Name]; dup {
				return nil, fmt.Errorf("%w：代理 %q 重复出现（重复会让同一段流量被计两次）",
					errFrpsListUnstable, p.Name)
			}
			seen[p.Name] = struct{}{}
			all = append(all, p)
		}

		// 完整性判定只认 total：累计数量达到它才算读全了。
		//
		// 「当前页不足一整页即成功」有两个漏洞：
		//   - frps 报 total=350，但接口在 250 条处开始提前截断——短页被当成
		//     「读完了」，剩下的 100 条凭空消失；
		//   - total 缺失时被解码成 0，任何短页都会「满足完成条件」。
		// 这不是普通的坏响应：采集器拿这份列表重建在线状态（setOnlineTunnels），
		// 没读到的代理会被判成离线，正在连接的用户直接「掉线」，还要等下一轮
		// 采集才恢复。所以宁可报错保住上一次的在线状态，也不采信残缺的列表。
		if total > 0 && len(all) >= total {
			if len(all) > total {
				return nil, fmt.Errorf("%w：已取 %d 条，超过上报的 total=%d",
					errFrpsListUnstable, len(all), total)
			}
			return all, nil
		}

		if len(out.Items) < frpsPageSize {
			// 走到这里说明 total 没被满足。特例：total 为 0 且一页为空，
			// 是 frps 明确的「没有任何代理」——这是真实状态，不是残缺响应；
			// 除此之外的短页一律不采信。
			if total == 0 && len(out.Items) == 0 && page == 1 {
				return all, nil
			}
			return nil, fmt.Errorf(
				"frps 代理列表不完整：已取 %d 条，上报 total=%d，第 %d 页仅返回 %d 条（每页 %d）",
				len(all), total, page, len(out.Items), frpsPageSize)
		}
	}
	// 取满 frpsMaxPages 页后仍有数据：宁可报错，也不返回一份不完整的列表。
	// 悄悄截断的后果是「没读到的那些隧道被判成离线」，而日志里看不出
	// 是分页被截断导致的——正是这次故障那种最难查的形态。
	return nil, fmt.Errorf("frps 代理数超过分页上限（%d 页 × %d 条），拒绝返回不完整列表",
		frpsMaxPages, frpsPageSize)
}

// getJSON 请求 frps 管理接口，解开 {code,msg,data} 后把 data 解到 out。
//
// 每一步不对都返回错误：HTTP 状态码非 200、响应不是合法 JSON、缺少 code、
// code 不是成功码、缺少 data、data 解不出来。**绝不返回「零值 + nil」**
// ——那等于告诉调用方「代理列表是空的」，而真实情况是我们根本没读懂响应。
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
	if env.Code == nil {
		return errors.New("frps 管理接口响应缺少 code 字段")
	}
	// frps 用 code 表达业务错误，此时 HTTP 状态码仍然是 200。
	if *env.Code != frpsSuccessCode {
		msg := strings.TrimSpace(env.Msg)
		if msg == "" {
			msg = "未提供原因"
		}
		return fmt.Errorf("frps 管理接口返回非成功码 %d: %s", *env.Code, msg)
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
