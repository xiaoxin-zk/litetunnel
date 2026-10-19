package frpsplugin

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

type newProxyContent struct {
	User               userInfo          `json:"user"`
	ProxyName          string            `json:"proxy_name"`
	ProxyType          string            `json:"proxy_type"`
	UseEncryption      bool              `json:"use_encryption"`
	UseCompression     bool              `json:"use_compression"`
	BandwidthLimit     string            `json:"bandwidth_limit"`
	BandwidthLimitMode string            `json:"bandwidth_limit_mode"`
	Group              string            `json:"group"`
	GroupKey           string            `json:"group_key"`
	Metas              map[string]string `json:"metas"`
	Annotations        map[string]string `json:"annotations"`
	RemotePort         int               `json:"remote_port"`
	CustomDomains      []string          `json:"custom_domains"`
	SubDomain          string            `json:"subdomain"`
	Locations          []string          `json:"locations"`
	HTTPUser           string            `json:"http_user"`
	HTTPPwd            string            `json:"http_pwd"`
	HostHeaderRewrite  string            `json:"host_header_rewrite"`
	Headers            map[string]string `json:"headers"`
	ResponseHeaders    map[string]string `json:"response_headers"`
	RouteByHTTPUser    string            `json:"route_by_http_user"`
	Sk                 string            `json:"sk"`
	AllowUsers         []string          `json:"allow_users"`
	Multiplexer        string            `json:"multiplexer"`
}

func (h *Handler) onNewProxy(req *request) response {
	var content newProxyContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return deny("代理参数解析失败")
	}
	if r, notReady := h.denyUntilGuardReady(); notReady {
		return r
	}

	u, ok := h.resolveUser(content.User.User, content.User.RunID, content.User.Metas)
	if !ok {
		return deny("客户端未完成认证，请重启客户端后重试")
	}
	if u.Status != model.UserStatusActive {
		return deny("账号已被禁用")
	}
	if blocked, exceeded, ok := h.svc.SessionGuard(content.User.RunID); ok {
		if blocked {
			return deny("账号已被禁用")
		}
		if exceeded {
			return deny("流量额度已用尽，请兑换流量或联系管理员")
		}
	} else {
		blocked, exceeded, ok := h.localAdmission(u.ID)
		if !ok {
			log.Printf("[plugin] 用户 %d 的准入状态在读取期间持续变化，无法确认是否已禁用，已拒绝注册", u.ID)
			return deny("账号状态正在变更，请稍后重试")
		}
		if blocked {
			return deny("账号已被禁用")
		}
		if exceeded {
			return deny("流量额度已用尽，请兑换流量或联系管理员")
		}
	}

	frpUser, tunnelName, ok := service.ParseProxyName(content.ProxyName)
	if !ok {
		log.Printf("[plugin] 代理名缺少用户前缀（proxy_name=%q, user=%q），已拒绝",
			content.ProxyName, content.User.User)
		return deny("代理名格式非法，请重新下载客户端配置")
	}
	if frpUser != service.FrpUserOf(u.ID) {
		log.Printf("[plugin] 代理名前缀与账号不匹配（proxy_name=%q, user=%q, 期望前缀=%q），已拒绝",
			content.ProxyName, content.User.User, service.FrpUserOf(u.ID))
		return deny("代理名与当前账号不匹配")
	}

	t, err := h.svc.FindTunnelByName(u.ID, tunnelName)
	if err != nil {
		return deny("隧道不存在或不属于当前账号，请重新下载客户端配置")
	}
	if t.Status != model.TunnelStatusActive {
		return deny("隧道已被停用")
	}
	if !strings.EqualFold(t.Type, content.ProxyType) {
		return deny("隧道协议与控制台下发的配置不一致")
	}

	switch t.Type {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		if content.RemotePort != t.RemotePort {
			return deny("远程端口与控制台下发的配置不一致")
		}
	case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
		if !domainMatched(t, &content) {
			return deny("访问域名与控制台下发的配置不一致")
		}
	}

	changed := false
	want := service.FormatBandwidth(h.svc.EffectiveBandwidth(u))
	if want != "" {
		if content.BandwidthLimit != want {
			content.BandwidthLimit = want
			changed = true
		}
		if content.BandwidthLimitMode != "server" {
			content.BandwidthLimitMode = "server"
			changed = true
		}
	} else if content.BandwidthLimit != "" {
		content.BandwidthLimit = ""
		content.BandwidthLimitMode = ""
		changed = true
	}

	if changed {
		return modify(content)
	}
	return allow()
}

func domainMatched(t *model.Tunnel, content *newProxyContent) bool {
	if t.Domain != "" {
		return len(content.CustomDomains) == 1 &&
			strings.EqualFold(strings.TrimSpace(content.CustomDomains[0]), t.Domain) &&
			content.SubDomain == ""
	}
	if t.Subdomain != "" {
		return strings.EqualFold(strings.TrimSpace(content.SubDomain), t.Subdomain) &&
			len(content.CustomDomains) == 0
	}
	return false
}
