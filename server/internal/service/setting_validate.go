package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func (s *Services) UpdateSettings(in map[SettingKey]string) error {
	if touchesDomainSettings(in) {
		s.domainMu.Lock()
		defer s.domainMu.Unlock()
	}

	view := func(k SettingKey) string {
		if v, ok := in[k]; ok && v != SecretMask {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(s.Settings.Get(k))
	}
	truthy := func(k SettingKey) bool {
		switch strings.ToLower(view(k)) {
		case "true", "1", "yes", "on":
			return true
		}
		return false
	}

	if truthy(KeySMTPEnabled) {
		host := view(KeySMTPHost)
		if host == "" {
			return fmt.Errorf("%w: 启用邮件前请填写 SMTP 服务器地址", ErrInvalidParam)
		}
		if view(KeySMTPUser) == "" || view(KeySMTPPassword) == "" {
			return fmt.Errorf("%w: 启用邮件前请填写 SMTP 账号与授权码", ErrInvalidParam)
		}
		switch strings.ToLower(view(KeySMTPTLS)) {
		case "ssl", "starttls", "none":
		default:
			return fmt.Errorf("%w: 邮件加密方式仅支持 ssl / starttls / none", ErrInvalidParam)
		}
		if s.Cfg.IsProd() && strings.EqualFold(view(KeySMTPTLS), "none") {
			return fmt.Errorf("%w: 生产环境禁止使用明文 SMTP", ErrInvalidParam)
		}
		port, err := strconv.Atoi(view(KeySMTPPort))
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("%w: SMTP 端口不合法", ErrInvalidParam)
		}
	}

	if truthy(KeyPaymentEnabled) {
		switch strings.ToLower(view(KeyPaymentProvider)) {
		case "easypay", "alipay", "wechat", "stripe":
		default:
			return fmt.Errorf("%w: 支付渠道仅支持 easypay / alipay / wechat / stripe", ErrInvalidParam)
		}
		if view(KeyPaymentAppID) == "" || view(KeyPaymentSecret) == "" {
			return fmt.Errorf("%w: 启用支付前请填写商户号与密钥", ErrInvalidParam)
		}
		if !strings.HasPrefix(view(KeyPaymentNotifyURL), "http") {
			return fmt.Errorf("%w: 支付回调地址必须是完整的 http(s) 地址", ErrInvalidParam)
		}
	}

	if ports := ParsePortList(view(KeyFirewallProtected)); len(ports) == 0 {
		return fmt.Errorf("%w: 保护端口列表不能为空，否则面板可能把自己锁在门外", ErrInvalidParam)
	}
	if _, panelPort, err := splitHostPortLoose(s.Cfg.UserAddr); err == nil && panelPort != "" {
		if p, err := strconv.Atoi(panelPort); err == nil {
			if !ParsePortList(view(KeyFirewallProtected))[p] {
				return fmt.Errorf("%w: 保护端口必须包含控制面自身端口 %d", ErrInvalidParam, p)
			}
		}
	}

	if truthy(KeyFirewallEnabled) {
		addr := view(KeyFirewallHelperAddr)
		if !strings.HasPrefix(addr, "http") {
			return fmt.Errorf("%w: 启用防火墙前请填写 helper 地址（形如 http://127.0.0.1:7849）", ErrInvalidParam)
		}
		token := view(KeyFirewallHelperToken)
		if len(token) < 16 {
			return fmt.Errorf("%w: helper 访问令牌至少 16 个字符，否则本机任意进程都能调用它改防火墙", ErrInvalidParam)
		}
	}

	if n, err := strconv.Atoi(view(KeyRegisterMaxPerIP)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单 IP 每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyRegisterMaxPerDomain)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单域名每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}

	allowRules, badAllow := ParseEmailDomainRules(view(KeyRegisterAllowDomains))
	blockRules, badBlock := ParseEmailDomainRules(view(KeyRegisterBlockDomains))
	if len(badAllow) > 0 {
		return fmt.Errorf("%w: 白名单里这些项无法识别：%s（可写 @qq.com、qq.com 或 *.edu.cn）",
			ErrInvalidParam, strings.Join(badAllow, "、"))
	}
	if len(badBlock) > 0 {
		return fmt.Errorf("%w: 黑名单里这些项无法识别：%s（可写 @qq.com、qq.com 或 *.edu.cn）",
			ErrInvalidParam, strings.Join(badBlock, "、"))
	}
	for _, a := range allowRules {
		for _, b := range blockRules {
			if a.String() == b.String() {
				return fmt.Errorf("%w: %s 同时出现在白名单与黑名单中，行为不可预期", ErrInvalidParam, a.String())
			}
		}
	}
	if truthy(KeyRegisterWhitelistOnly) && len(allowRules) == 0 {
		return fmt.Errorf("%w: 选择「仅允许白名单域名注册」时必须先填写白名单", ErrInvalidParam)
	}

	if n, err := strconv.Atoi(view(KeyRegisterNonWhitelistQuota)); err != nil || n < 0 || n > 100000 {
		return fmt.Errorf("%w: 白名单外域名注册名额需为 0-100000 的整数（0 表示直接拒绝）", ErrInvalidParam)
	}

	if h := strings.TrimSpace(view(KeyGatewayHost)); h != "" {
		if strings.ContainsAny(h, " \t\r\n/\\:@") {
			return fmt.Errorf("%w: 网关地址只填主机名或 IP，不要带协议、端口或路径（端口请填在下面一项）", ErrInvalidParam)
		}
	}
	if n, err := strconv.Atoi(view(KeyGatewayPort)); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: 网关端口需为 1-65535 的整数", ErrInvalidParam)
	}

	if n, err := strconv.Atoi(view(KeyAPIRatePerMinute)); err != nil || n < 1 || n > 100000 {
		return fmt.Errorf("%w: 接口每分钟请求上限需为 1-100000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyAPIRateBurst)); err != nil || n < 1 || n > 10000 {
		return fmt.Errorf("%w: 接口突发容量需为 1-10000 的整数", ErrInvalidParam)
	}

	if err := validateDomainSettings(view, s.Settings.Get); err != nil {
		return err
	}

	firewallWasOn := s.Settings.Bool(KeyFirewallEnabled)

	if err := s.Settings.SetMany(in); err != nil {
		return err
	}

	needsReconcile := false
	for _, k := range []SettingKey{KeyFirewallEnabled, KeyFirewallAutoOpen, KeyFirewallAutoClose} {
		if _, changed := in[k]; changed {
			needsReconcile = true
		}
	}
	if needsReconcile && (s.Settings.Bool(KeyFirewallEnabled) || !firewallWasOn) {
		s.KickFirewall()
	}
	return nil
}

func validateDomainSettings(view, current func(SettingKey) string) error {
	panel := normalizeDomainValue(view(KeyDomainPanel))
	if panel == "" {
		if current(KeyDomainPanel) != "" {
			return fmt.Errorf("%w: 面板域名不能为空：Caddy 需要它签发证书，找回密码邮件也要用它拼链接", ErrInvalidParam)
		}
		return nil
	}
	if err := checkPanelDomain(panel); err != nil {
		return fmt.Errorf("%w: 面板域名不合法（%s）", ErrInvalidParam, err.Error())
	}

	tunnel := normalizeDomainValue(view(KeyDomainTunnel))
	if tunnel != "" {
		if err := checkDomain(tunnel); err != nil {
			return fmt.Errorf("%w: 隧道根域名不合法（%s）", ErrInvalidParam, err.Error())
		}
		if tunnel == panel {
			return fmt.Errorf("%w: 隧道根域名不能与面板域名相同：同一个域名既要由 Caddy 提供控制台、又要按子域转发隧道，"+
				"证书配额与排查都会立刻变成灾难", ErrInvalidParam)
		}
		if strings.TrimSpace(view(KeyDomainDNSProvider)) == "" {
			return fmt.Errorf("%w: 已填写隧道根域名但未选择 DNS 服务商：泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证", ErrInvalidParam)
		}
	}

	switch strings.ToLower(strings.TrimSpace(view(KeyDomainHTTPSMode))) {
	case "", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E:
	default:
		return fmt.Errorf("%w: HTTPS 隧道模式只能是 %s（证书留在 Caddy）或 %s（证书留在本地网站）",
			ErrInvalidParam, tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E)
	}

	if ip := strings.TrimSpace(view(KeyDomainExpectedIP)); ip != "" && net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: DNS 检查的期望地址不是合法 IP", ErrInvalidParam)
	}

	if addr := strings.TrimSpace(view(KeyDomainHelperAddr)); addr != "" {
		if _, err := tlscfg.ParseBaseURL(addr); err != nil {
			return fmt.Errorf("%w: 配置服务地址不合法（%s），需形如 http://127.0.0.1:7850", ErrInvalidParam, err.Error())
		}
	}
	if token := view(KeyDomainHelperToken); token != "" && len(token) < 16 {
		return fmt.Errorf("%w: 配置服务访问令牌至少 16 个字符，否则本机任意进程都能让它重写 TLS 配置并重启容器", ErrInvalidParam)
	}
	return nil
}

var domainSettingKeys = []SettingKey{
	KeyDomainPanel,
	KeyDomainTunnel,
	KeyDomainACMEEmail,
	KeyDomainDNSProvider,
	KeyDomainDNSArgs,
	KeyDomainDNSCredential,
	KeyDomainHTTPSMode,
}

func touchesDomainSettings(in map[SettingKey]string) bool {
	for _, k := range domainSettingKeys {
		if _, ok := in[k]; ok {
			return true
		}
	}
	return false
}
