package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const helperTimeout = 10 * time.Second

type HelperBackend struct {
	base   string
	token  string
	client *http.Client
}

func NewHelperBackend(base, token string) *HelperBackend {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base != "" && !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	return &HelperBackend{
		base:  base,
		token: token,
		client: &http.Client{
			Timeout: helperTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *HelperBackend) Name() string { return "helper" }

const probeCacheTTL = 5 * time.Second

type probeEntry struct {
	at     time.Time
	ok     bool
	err    error
	reason string
}

var probeCache = struct {
	sync.Mutex
	m map[string]probeEntry
}{m: map[string]probeEntry{}}

func (h *HelperBackend) probe() (bool, error) {
	probeCache.Lock()
	e, hit := probeCache.m[h.base]
	probeCache.Unlock()
	if hit && time.Since(e.at) < probeCacheTTL {
		return e.ok, e.err
	}
	var out helperHealth
	err := h.get("/health", &out)
	ok := err == nil && out.Available
	reason := out.Reason
	if err == nil && !out.Available && reason == "" {
		reason = "宿主机 helper 报告没有可用的防火墙后端"
	}
	probeCache.Lock()
	probeCache.m[h.base] = probeEntry{at: time.Now(), ok: ok, err: err, reason: reason}
	probeCache.Unlock()
	return ok, err
}

func (h *HelperBackend) probeReason() string {
	probeCache.Lock()
	defer probeCache.Unlock()
	return probeCache.m[h.base].reason
}

func (h *HelperBackend) Available() bool {
	if h.base == "" {
		return false
	}
	ok, _ := h.probe()
	return ok
}

func (h *HelperBackend) Status() (bool, error) {
	var out helperHealth
	if err := h.get("/health", &out); err != nil {
		return false, err
	}
	if out.Error != "" {
		return false, errors.New(out.Error)
	}
	return out.Enabled, nil
}

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

func (h *HelperBackend) Reason() string {
	if h.base == "" {
		return "未配置宿主机防火墙 helper 地址，请在「系统设置 → 端口与防火墙」中填写"
	}
	if h.token == "" {
		return "未配置 helper 访问令牌，请在「系统设置 → 端口与防火墙」中填写"
	}
	ok, err := h.probe()
	if err != nil {
		return fmt.Sprintf("无法连接宿主机 helper（%s），请确认 lt-fw 服务已启动（%v）", h.base, err)
	}
	if !ok {
		if r := h.probeReason(); r != "" {
			return r
		}
		return "宿主机 helper 报告没有可用的防火墙后端"
	}
	return ""
}

type helperHealth struct {
	Backend   string `json:"backend"`
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
	Error     string `json:"error"`
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
