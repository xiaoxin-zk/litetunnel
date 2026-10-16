package service

import (
	"fmt"
	"net"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// normalizeInput 统一校验并清洗入参。
func (s *Services) normalizeInput(u *model.User, g *model.Group, in TunnelInput) (model.Tunnel, error) {
	var out model.Tunnel

	name := strings.TrimSpace(in.Name)
	if len(name) < 1 || len(name) > 32 || !IsSafeName(name) {
		return out, fmt.Errorf("%w: 隧道名称需为 1-32 位字母、数字或下划线", ErrInvalidParam)
	}
	// 名称会拼进 frp 的 proxy 名（形如 {user}.{name}），前缀保留给系统使用。
	if strings.HasPrefix(strings.ToLower(name), "lt") {
		return out, fmt.Errorf("%w: 隧道名称不能以 lt 开头", ErrInvalidParam)
	}

	ptype := strings.ToLower(strings.TrimSpace(in.Type))
	allowed := AllowedProtocols(g)
	if !allowed[ptype] {
		return out, ErrProtocolDenied
	}
	switch ptype {
	case model.ProxyTypeTCP, model.ProxyTypeUDP, model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
	default:
		return out, ErrProtocolDenied
	}

	// HTTPS 隧道与 HTTP 隧道的入口不是同一条：HTTP 走 Caddy 的 443，
	// 由 Caddy 用泛域名证书终止 TLS 后转发给 frps；HTTPS 则由 frps 在独立
	// 端口上按 SNI 透传原始 TLS 连接，证书留在本地网站——而那条入口只在
	// 端到端模式下存在。
	//
	// 不拦的话，用户会创建一个永远打不开的隧道，然后去查本地网站的配置、
	// 防火墙、证书，一路查到最后才发现是平台根本不提供这条入口。
	if ptype == model.ProxyTypeHTTPS && !s.HTTPSProxyEntryEnabled() {
		return out, ErrNoHTTPSProxyEntry
	}

	if in.LocalPort < 1 || in.LocalPort > 65535 {
		return out, fmt.Errorf("%w: 本地端口需在 1-65535 之间", ErrInvalidParam)
	}
	localIP := strings.TrimSpace(in.LocalIP)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil && !isValidHostname(localIP) {
		return out, fmt.Errorf("%w: 本地地址格式不正确", ErrInvalidParam)
	}

	out = model.Tunnel{
		Name:           name,
		Type:           ptype,
		LocalIP:        localIP,
		LocalPort:      in.LocalPort,
		Remark:         truncate(in.Remark, 200),
		UseEncryption:  in.UseEncryption,
		UseCompression: in.UseCompression,
		Status:         model.TunnelStatusActive,
	}

	if ptype == model.ProxyTypeHTTP || ptype == model.ProxyTypeHTTPS {
		domain, sub, err := s.normalizeDomain(g, in)
		if err != nil {
			return out, err
		}
		out.Domain = domain
		out.Subdomain = sub
	} else {
		out.RemotePort = in.RemotePort
	}
	return out, nil
}

// normalizeDomain 处理 HTTP/HTTPS 的域名或二级域名。
func (s *Services) normalizeDomain(g *model.Group, in TunnelInput) (domain, sub string, err error) {
	domain = strings.ToLower(strings.TrimSpace(in.Domain))
	sub = strings.ToLower(strings.TrimSpace(in.Subdomain))

	if domain == "" && sub == "" {
		return "", "", fmt.Errorf("%w: HTTP/HTTPS 隧道需指定域名或二级域名", ErrInvalidParam)
	}
	if domain != "" {
		if !g.AllowCustomDomain {
			return "", "", ErrDomainDenied
		}
		if !isValidHostname(domain) {
			return "", "", fmt.Errorf("%w: 域名格式不正确", ErrInvalidParam)
		}
		// 自定义域名必须落在平台泛域名之下，防止用户劫持他人域名。
		//
		// 用 TunnelDomain() 而不是 Cfg.TunnelDomain：管理员在「域名与证书」
		// 里改完域名后，面板容器不会重启，照 Cfg 判权会让「新域名的子域
		// 被拒绝、旧域名的子域被放行」——而渲染出的 Caddyfile 里只有新域名。
		td := s.TunnelDomain()
		if td != "" && !strings.HasSuffix(domain, "."+td) && domain != td {
			return "", "", fmt.Errorf("%w: 仅允许使用 *.%s 下的域名", ErrDomainDenied, td)
		}
		return domain, "", nil
	}

	if s.TunnelDomain() == "" {
		return "", "", fmt.Errorf("%w: 平台未配置泛域名，暂不支持二级域名", ErrInvalidParam)
	}
	if !IsSafeName(sub) {
		return "", "", fmt.Errorf("%w: 二级域名仅允许字母、数字或下划线", ErrInvalidParam)
	}
	return "", sub, nil
}

func isValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
