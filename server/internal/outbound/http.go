// Package outbound 统一收口控制面主动发起的 HTTP 请求。
//
// 面板里有若干「地址由管理员填写、请求由服务端发起」的功能（告警 Webhook、
// 宿主机 helper 等）。这类地址如果只做字符串校验，就会变成从内网发起请求的跳板：
// 把 Webhook 指向云厂商元数据服务，就能借面板的身份读到实例凭据。因此策略收在一处：
//
//   - 保存时校验 scheme / 主机 / 端口，拒绝已知的元数据地址；
//   - 拨号时按真实解析出的 IP 再校验一次，防止 DNS rebinding 绕过保存时的校验；
//   - 不跟随重定向：3xx 会换一个未经校验的目标，等于绕过上面两条；
//   - 共享一个带超时与连接池的 Client，避免每次推送新建 Transport。
//
// 私有网段与回环地址是**允许**的：自建 ntfy / Gotify 常跑在 127.0.0.1 或
// 192.168.x 上，禁掉它们会让告警在最常见的自托管场景里直接不可用。
// 被拒绝的是链路本地地址（含 169.254.169.254）、未指定地址、组播地址，
// 以及已知的元数据主机名——这些地址上不存在合法的通知接收端。
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// RequestTimeout 是单次出站请求（含 DNS、连接、TLS、读响应）的总时限。
	RequestTimeout = 10 * time.Second
	maxURLLen      = 500
)

// ErrBlockedTarget 表示目标地址被出站策略拒绝（元数据、链路本地等）。
var ErrBlockedTarget = errors.New("目标地址被出站策略拒绝")

// 云厂商元数据服务的固定主机名。拿到它们就等于拿到实例凭据，
// 因此无论管理员填什么都要拒绝。
var blockedHostnames = map[string]struct{}{
	"metadata":                   {},
	"metadata.google.internal":   {},
	"metadata.goog":              {},
	"instance-data":              {},
	"instance-data.ec2.internal": {},
}

// 无法用网段规则覆盖的元数据地址（网段规则会把整段链路本地拒掉，
// 这里额外补上阿里云与 AWS 的 IPv6 元数据地址）。
var blockedIPs = map[netip.Addr]struct{}{
	netip.MustParseAddr("100.100.100.200"): {}, // 阿里云
	netip.MustParseAddr("fd00:ec2::254"):   {}, // AWS IPv6
}

// ValidateHTTPURL 校验管理员填写的出站地址，返回规范化后的结果。
// 错误信息里只回显主机名或端口，不回显完整地址——地址本身可能就是凭据
// （Slack / 飞书 / Discord 的 token 都在路径里）。
func ValidateHTTPURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("地址不能为空")
	}
	if len(trimmed) > maxURLLen {
		return "", fmt.Errorf("地址过长（上限 %d 字节）", maxURLLen)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", errors.New("地址无法解析")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("只支持 http/https，实际是 %q", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("地址里不能带用户名密码")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("地址缺少主机名")
	}
	if _, blocked := blockedHostnames[strings.ToLower(host)]; blocked {
		return "", fmt.Errorf("不允许指向云元数据主机（%s）", host)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("端口不合法：%s", port)
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && blockedIP(ip) {
		return "", fmt.Errorf("不允许指向该地址（%s）", host)
	}
	return u.String(), nil
}

// blockedIP 判断解析结果是否落在禁止范围。
func blockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	_, blocked := blockedIPs[ip]
	return blocked
}

var dialer = &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

// dialContext 在真正建连前校验目标 IP：保存时的校验只看到域名，
// DNS 可以在两次解析之间返回内网地址（DNS rebinding）。
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if blockedIP(ip) {
			return nil, ErrBlockedTarget
		}
		return dialer.DialContext(ctx, network, addr)
	}
	if _, blocked := blockedHostnames[strings.ToLower(host)]; blocked {
		return nil, ErrBlockedTarget
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if blockedIP(ip) {
			lastErr = ErrBlockedTarget
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrBlockedTarget
	}
	return nil, lastErr
}

var client = &http.Client{
	Timeout: RequestTimeout,
	Transport: &http.Transport{
		// 刻意不使用 HTTP(S)_PROXY：一旦走代理，真正建连的是代理进程，
		// 我们的 IP 策略就看不到目标地址，等于把上面的校验全部绕过。
		Proxy:                 nil,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
	},
	// 3xx 会指向一个没有经过校验的目标，跟随它就等于绕过全部出站策略。
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Client 返回共享的出站客户端。调用方不应修改它（需要不同策略时请自行复制）。
func Client() *http.Client { return client }

// SanitizeError 去掉错误里携带的完整 URL。
// Webhook 地址本身就是凭据，原样写进日志等于把 token 抄进日志。
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	if uerr.URL == "" {
		return uerr.Err
	}
	if u, perr := url.Parse(uerr.URL); perr == nil && u.Host != "" {
		return fmt.Errorf("%s %s://%s 失败: %w", uerr.Op, u.Scheme, u.Host, uerr.Err)
	}
	return uerr.Err
}
