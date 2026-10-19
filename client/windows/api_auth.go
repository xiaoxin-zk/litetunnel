package main

import (
	"errors"
	"net/url"
	"strings"
)

func checkServerURL(raw string, _ bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("请填写服务器地址")
	}
	if !strings.Contains(raw, "://") {
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

func (a *App) resolveBase(serverURL string) (string, error) {
	if base := defaultServerURL(); base != "" {
		return checkServerURL(base, true)
	}
	return checkServerURL(serverURL, false)
}
