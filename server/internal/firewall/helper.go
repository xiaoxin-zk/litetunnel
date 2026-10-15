package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// helperTimeout 是调用 helper 的超时。
//
// 比本地命令超时略长：helper 可能正在等 iptables 锁，
// 但也不能太长——写操作会阻塞建隧道的请求。
const helperTimeout = 10 * time.Second

// HelperBackend 通过宿主机上的 lt-fw helper 执行防火墙操作。
//
// # 为什么面板要有这样一个「远程」后端
//
// 面板容器**不持有任何防火墙写权限**：既没有 NET_ADMIN，也不直接调用
// iptables。它把写操作转发给宿主机上的 helper，由后者在受控条件下执行。
//
// 这样切分之后，即使面板被完全控制，攻击者能做的也只是
// 「放行/关闭端口池内的端口」——保护端口依然动不了，
// 更拿不到主机防火墙的完全控制权。
//
// 地址通常是 127.0.0.1:7849：面板以 host 网络模式运行，直接可达宿主机回环。
type HelperBackend struct {
	base   string
	token  string
	client *http.Client
}

// NewHelperBackend 构造 helper 客户端。base 形如 http://127.0.0.1:7849。
func NewHelperBackend(base, token string) *HelperBackend {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base != "" && !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	return &HelperBackend{
		base:  base,
		token: token,
		// 不跟随重定向：helper 不该有重定向，跟了反而可能被引到别处。
		client: &http.Client{
			Timeout: helperTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *HelperBackend) Name() string { return "helper" }

// Available 判断 helper 是否可达。
//
// 这是面板决定「能不能操作防火墙」的唯一依据：
// helper 没起来时，面板应当明确告诉管理员去检查它，
// 而不是悄悄退回到「容器内直连 iptables」那条已经废弃的路径。
func (h *HelperBackend) Available() bool {
	if h.base == "" {
		return false
	}
	var out helperHealth
	return h.get("/health", &out) == nil
}

func (h *HelperBackend) Status() (bool, error) {
	var out helperHealth
	if err := h.get("/health", &out); err != nil {
		return false, err
	}
	return out.Enabled, nil
}

// ListRules 取回 helper 递归展开后的放行端口。
//
// 展开在 helper 侧完成：解析规则需要读 iptables，那是特权操作。
// 面板拿到的已经是结构化结果，不需要也不应该再自己去读规则集。
func (h *HelperBackend) ListRules() ([]Rule, error) {
	var out struct {
		Rules []Rule `json:"rules"`
	}
	if err := h.get("/rules", &out); err != nil {
		return nil, err
	}
	return out.Rules, nil
}

func (h *HelperBackend) AddPort(port int, proto string) error {
	return h.postPort("/ports/open", port, proto)
}

func (h *HelperBackend) RemovePort(port int, proto string) error {
	return h.postPort("/ports/close", port, proto)
}

// Reason 返回 helper 配置缺失的原因，供界面提示用。
func (h *HelperBackend) Reason() string {
	if h.base == "" {
		return "未配置宿主机防火墙 helper 地址，请在「系统设置 → 端口与防火墙」中填写"
	}
	if h.token == "" {
		return "未配置 helper 访问令牌，请在「系统设置 → 端口与防火墙」中填写"
	}
	if !h.Available() {
		return fmt.Sprintf("无法连接宿主机 helper（%s），请确认 lt-fw 服务已启动", h.base)
	}
	return ""
}

type helperHealth struct {
	Backend   string `json:"backend"`
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
}

func (h *HelperBackend) get(path string, out any) error {
	if h.base == "" || h.token == "" {
		return fmt.Errorf("helper 未配置")
	}
	req, err := http.NewRequest(http.MethodGet, h.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	return h.do(req, out)
}

func (h *HelperBackend) postPort(path string, port int, proto string) error {
	if h.base == "" || h.token == "" {
		return fmt.Errorf("helper 未配置")
	}
	body, err := json.Marshal(map[string]any{"port": port, "proto": proto})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, h.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	return h.do(req, nil)
}

// do 执行请求并统一处理错误。
//
// helper 返回的错误信息（例如「端口在保护列表中」）要原样带回去：
// 那是管理员判断「为什么操作没生效」的唯一线索，
// 换成笼统的「操作失败」会让排查变成猜谜。
func (h *HelperBackend) do(req *http.Request, out any) error {
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("连接宿主机 helper 失败: %w", err)
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
		return fmt.Errorf("helper 返回状态码 %d", resp.StatusCode)
	}

	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
