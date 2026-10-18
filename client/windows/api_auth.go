package main

import (
	"errors"
	"net/url"
	"strings"
)

// checkServerURL 校验并归一化一个服务端地址。
//
// 地址同时支持 http 与 https。HTTP 适用于未配置域名证书的部署，但会明文传输
// API Key；公网使用时应优先配置 HTTPS。
func checkServerURL(raw string, _ bool) (string, error) {
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
	default:
		return "", errors.New("仅支持 http 或 https 协议")
	}
	if u.Host == "" {
		return "", errors.New("服务器地址缺少主机名")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
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
