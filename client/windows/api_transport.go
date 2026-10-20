package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// apiStatusError 保留 HTTP 状态码：上层需要区分「网络问题」和
// 「凭据已被服务端拒绝」（账号被删除/禁用、API Key 被轮换）。
type apiStatusError struct {
	Status  int
	Message string
}

func (e *apiStatusError) Error() string { return e.Message }

// unauthorized 判断是否属于「凭据失效」。只认 401：
// 403 还可能是 IP 封禁、只读接口等业务限制，不该据此清掉本地凭据。
func unauthorized(err error) bool {
	var se *apiStatusError
	if errors.As(err, &se) {
		return se.Status == http.StatusUnauthorized
	}
	return false
}

func (a *App) getJSON(ctx context.Context, endpoint, token string, out any) error {
	body, err := a.do(ctx, http.MethodGet, endpoint, token, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

const maxResponseBytes = 4 << 20

const configRevHeader = "X-Config-Rev"

func (a *App) getRaw(ctx context.Context, endpoint, token string, out *string) error {
	text, _, err := a.getRawWithRev(ctx, endpoint, token)
	if err != nil {
		return err
	}
	*out = text
	return nil
}

func (a *App) getRawWithRev(ctx context.Context, endpoint, token string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("无法连接服务器: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		err := &apiStatusError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("服务器返回状态码 %d", resp.StatusCode),
		}
		if token != "" && unauthorized(err) {
			a.credentialRejected()
		}
		return "", "", err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", "", err
	}
	if len(data) > maxResponseBytes {
		return "", "", fmt.Errorf("服务器响应超过客户端上限(%d MiB)", maxResponseBytes>>20)
	}
	return string(data), strings.TrimSpace(resp.Header.Get(configRevHeader)), nil
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

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("服务器响应超过客户端上限（%d MiB）", maxResponseBytes>>20)
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
		err := &apiStatusError{Status: resp.StatusCode, Message: clampStatusText(msg)}
		// 带着已保存的凭据仍被拒绝（401）：账号很可能已被删除或禁用，
		// 必须让客户端退出登录，否则界面会一直停在「已接入」但什么都做不了。
		if token != "" && unauthorized(err) {
			a.credentialRejected()
		}
		return nil, err
	}
	return env.Data, nil
}
