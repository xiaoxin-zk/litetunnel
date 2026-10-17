package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// checkServerURL 校验并归一化一个服务端地址。
//
// 主线只有一条：**凭据只能走 HTTPS**。
//
// 接入之后每一轮同步都带着长期 API Key（Authorization: Bearer …），
// 而 API Key 是「泄露一次、长期可用」的东西：明文 HTTP 的链路上任何一跳
// （同一个 WiFi、机房上游、运营商）都能把它抄走，然后以该用户的身份接入
// 隧道、改隧道配置。地址是用户在界面上填的，所以必须在填的时候就拒绝。
//
// 唯一的例外是本地调试：开发构建（没有注入地址）面向 127.0.0.1 起面板时
// 允许 http，因为那条链路不出本机。构建注入的地址一律要求 https——
// 正式客户端的内置地址如果写成 http://IP，那就等于把 API Key 明文发出去。
func checkServerURL(raw string, injected bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("请填写服务器地址")
	}
	if !strings.Contains(raw, "://") {
		// 未写协议时按 https 处理，避免凭据走明文。
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("服务器地址格式不正确")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if injected {
			return "", errors.New("内置地址必须使用 https：明文 HTTP 会把 API Key 暴露在链路上")
		}
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New(
				"服务端必须使用 https：明文 HTTP 会把 API Key 暴露给链路上的任何一跳。" +
					"http 只允许用于本机调试（127.0.0.1 / localhost / ::1）")
		}
	default:
		return "", errors.New("仅支持 http 或 https 协议")
	}
	if u.Host == "" {
		return "", errors.New("服务器地址缺少主机名")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// isLoopbackHost 判断主机名是否指向本机。
func isLoopbackHost(host string) bool {
	// URL 里的 IPv6 字面量带方括号，如 http://[::1]:8080。
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// resolveBase 统一解析服务端地址。
//
// 构建注入的地址优先：正式客户端只认内置地址，用户无从篡改，
// 也就不会被诱导连到钓鱼服务器。未注入时才用界面上填写的（仅调试构建）。
func (a *App) resolveBase(serverURL string) (string, error) {
	if base := defaultServerURL(); base != "" {
		// 注入的地址同样要过校验：地址是 CI 里的 secret，填错时客户端
		// 应当直接拒绝发送凭据，而不是把长期 API Key 明文发出去。
		return checkServerURL(base, true)
	}
	return checkServerURL(serverURL, false)
}

// getJSON / getRaw / do 都接受 ctx：同步整轮带截止时间时，
// 在途的请求也要能被中断——否则截止只是「不再派发新任务」，
// 已发出的请求仍会等到各自的超时，截止时间形同虚设。
// 不需要截止时间的调用方传 context.Background()（仍有 http.Client
// 的 Timeout 兜底）。
func (a *App) getJSON(ctx context.Context, endpoint, token string, out any) error {
	body, err := a.do(ctx, http.MethodGet, endpoint, token, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (a *App) getRaw(ctx context.Context, endpoint, token string, out *string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接服务器: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回状态码 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	*out = string(data)
	return nil
}

func (a *App) do(ctx context.Context, method, endpoint, token string, payload []byte) (json.RawMessage, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接服务器，请检查地址与网络: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("服务器响应格式异常（状态码 %d）", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || env.Code != 0 {
		msg := env.Message
		if msg == "" {
			msg = fmt.Sprintf("请求失败（状态码 %d）", resp.StatusCode)
		}
		return nil, errors.New(msg)
	}
	return env.Data, nil
}
