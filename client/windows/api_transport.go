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

// maxResponseBytes 是单次响应的读取上限。
//
// 超限必须显式报错而不是静默截断：截断后的 JSON 解析会失败，错误信息
// 只是一句「响应格式异常」，看不出真正原因是「响应太大」。
const maxResponseBytes = 4 << 20

// configRevHeader 是服务端在配置响应里给出的摘要头(老服务端没有)。
const configRevHeader = "X-Config-Rev"

// getRaw 拉取正文(忽略摘要)。
func (a *App) getRaw(ctx context.Context, endpoint, token string, out *string) error {
	text, _, err := a.getRawWithRev(ctx, endpoint, token)
	if err != nil {
		return err
	}
	*out = text
	return nil
}

// getRawWithRev 拉取正文,并返回服务端**随这份正文**给出的摘要。
//
// 摘要必须与正文同源:清单里的 config_rev 是另一次渲染算出来的,两次请求
// 之间管理端改了隧道的话,客户端会把「新正文 + 旧摘要」配成一对缓存下来,
// 之后就可能一直跑着过时的配置(见 sync.go 里 cachedConfig 的说明)。
//
// 老服务端没有这个头,返回空串——调用方按「摘要未知」处理,不记账。
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
		return "", "", fmt.Errorf("服务器返回状态码 %d", resp.StatusCode)
	}
	// 多读一个字节用于判断是否超限。
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
		// 不截断着往下解析：报「格式异常」会把真正的原因（响应太大）
		// 藏起来，用户与日志都无从排查。
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
		// 服务端文案会原样进入 Wails 事件、日志和界面提示。异常响应可能
		// 带上整段 HTML 或堆栈，不截断就会在每次状态事件里重复传输。
		return nil, errors.New(clampStatusText(msg))
	}
	return env.Data, nil
}
