package service

import (
	"fmt"
	"net"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (s *Services) normalizeInput(u *model.User, g *model.Group, in TunnelInput) (model.Tunnel, error) {
	var out model.Tunnel

	name := strings.TrimSpace(in.Name)
	if len(name) < 1 || len(name) > 32 || !IsSafeName(name) {
		return out, fmt.Errorf("%w: 隧道名称需为 1-32 位字母、数字或下划线", ErrInvalidParam)
	}
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
