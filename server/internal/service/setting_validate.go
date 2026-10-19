package service

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/outbound"
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

	if n, err := strconv.Atoi(view(KeyAuditRetentionDays)); err != nil || n < 0 || n > 3650 {
		return fmt.Errorf("%w: 操作日志保留天数需为 0-3650 的整数（0 表示永久保留，仅可手动清理）", ErrInvalidParam)
	}

	if err := validateSiteBrand(view); err != nil {
		return err
	}

	if err := validateOAuthSettings(view, truthy); err != nil {
		return err
	}

	if n, err := strconv.Atoi(strings.TrimSpace(view(KeyBackupRetention))); err != nil || n < 1 || n > 60 {
		return fmt.Errorf("%w: 备份保留份数需为 1-60 的整数", ErrInvalidParam)
	}

	if err := validateAlertSettings(view); err != nil {
		return err
	}

	if _, invalid := ParseBlocklist(view(KeyIPBlacklist)); len(invalid) > 0 {
		if len(invalid) > 5 {
			invalid = invalid[:5]
		}
		return fmt.Errorf("%w: IP 黑名单里有无法识别的条目：%s（每行一个 IP 或 CIDR）",
			ErrInvalidParam, strings.Join(invalid, "、"))
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

const (
	siteLogoDataURLMax = 360000 // 约 256KB 图片（base64 后膨胀 4/3）
	siteSVGSourceMax   = 100 * 1024
	siteSVGDataURLMax  = 140000
	siteSubtitleMax    = 120
	siteHomeContentMax = 20000
)

var siteLogoPrefixes = []string{
	"data:image/png;base64,",
	"data:image/jpeg;base64,",
	"data:image/webp;base64,",
	"data:image/gif;base64,",
}

const siteSVGPrefix = "data:image/svg+xml;base64,"

// SVG 只做静态图片使用，因此把能执行代码或引用外部资源的写法整类拒掉，
// 而不是依赖前端永远只用 <img> 渲染这一条约定。
var (
	svgBlockedTokens = []string{
		"<script", "<foreignobject", "<!entity", "<!doctype", "javascript:",
		"url(http", "url(//", "url('http", "url(\"http",
	}
	svgEventHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	svgExternalRef  = regexp.MustCompile(`(?i)(xlink:href|href)\s*=\s*["']\s*(https?:)?//`)
)

func validateSVGLogo(logo string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(logo, siteSVGPrefix))
	if err != nil {
		return fmt.Errorf("%w: SVG 内容不是合法的 base64", ErrInvalidParam)
	}
	if len(raw) > siteSVGSourceMax {
		return fmt.Errorf("%w: SVG 体积超限，压缩到 100KB 以内再上传", ErrInvalidParam)
	}
	low := strings.ToLower(string(raw))
	for _, tok := range svgBlockedTokens {
		if strings.Contains(low, tok) {
			return fmt.Errorf("%w: SVG 里含有不允许的内容（%s），请导出为 png 后上传", ErrInvalidParam, tok)
		}
	}
	if svgEventHandler.MatchString(low) {
		return fmt.Errorf("%w: SVG 里含有事件属性（on*=），请导出为 png 后上传", ErrInvalidParam)
	}
	if svgExternalRef.MatchString(low) {
		return fmt.Errorf("%w: SVG 不得引用外部资源", ErrInvalidParam)
	}
	return nil
}

// validateSiteBrand 校验站点品牌字段。Logo 直接以 data URL 存设置表，
// 不依赖对象存储，因此必须限制类型与体积，避免把设置行写爆。
func validateSiteBrand(view func(SettingKey) string) error {
	if logo := strings.TrimSpace(view(KeySiteLogo)); logo != "" {
		if strings.HasPrefix(logo, siteSVGPrefix) {
			if len(logo) > siteSVGDataURLMax {
				return fmt.Errorf("%w: SVG 体积超限，压缩到 100KB 以内再上传", ErrInvalidParam)
			}
			if err := validateSVGLogo(logo); err != nil {
				return err
			}
			return validateSiteBrandRest(view)
		}
		ok := false
		for _, p := range siteLogoPrefixes {
			if strings.HasPrefix(logo, p) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: 站点 Logo 只支持 png/jpeg/webp/gif/svg 的 data URL（形如 data:image/png;base64,...），"+
				"不接受外链", ErrInvalidParam)
		}
		if len(logo) > siteLogoDataURLMax {
			return fmt.Errorf("%w: 站点 Logo 体积超限，压缩到 256KB 以内再上传", ErrInvalidParam)
		}
	}
	return validateSiteBrandRest(view)
}

func validateSiteBrandRest(view func(SettingKey) string) error {
	if n := len([]rune(view(KeySiteSubtitle))); n > siteSubtitleMax {
		return fmt.Errorf("%w: 站点副标题不能超过 %d 字", ErrInvalidParam, siteSubtitleMax)
	}
	if api := strings.TrimSpace(view(KeySiteFrontendURL)); api != "" {
		if !strings.HasPrefix(api, "https://") && !strings.HasPrefix(api, "http://") {
			return fmt.Errorf("%w: 服务器地址要填完整地址，以 http:// 或 https:// 开头，例如 https://panel.example.com", ErrInvalidParam)
		}
		if strings.HasSuffix(api, "/") {
			return fmt.Errorf("%w: 服务器地址不要以 / 结尾", ErrInvalidParam)
		}
		if len(api) > 200 {
			return fmt.Errorf("%w: 服务器地址过长", ErrInvalidParam)
		}
	}
	if n := len(view(KeySiteHomeContent)); n > siteHomeContentMax {
		return fmt.Errorf("%w: 首页内容不能超过 %d 字节", ErrInvalidParam, siteHomeContentMax)
	}
	return nil
}

// validateAlertSettings 保证告警阈值落在有意义区间：
// 百分比越界会让规则永不触发或每次采样都触发；Webhook 不是 http(s) 或目标地址为空，
// 则告警在推送阶段才失败，界面上看起来「已启用」却一条都发不出去。
func validateAlertSettings(view func(SettingKey) string) error {
	upstream := view(KeyAlertWebhook)
	if upstream != "" {
		if _, err := outbound.ValidateHTTPURL(upstream); err != nil {
			return fmt.Errorf("%w: 告警 Webhook %v", ErrInvalidParam, err)
		}
	}
	if upstream == "" {
		switch strings.ToLower(strings.TrimSpace(view(KeyAlertEnabled))) {
		case "true", "1", "yes", "on":
			return fmt.Errorf("%w: 启用告警前请先填写 Webhook 地址，否则告警无处可发", ErrInvalidParam)
		}
	}
	for _, item := range []struct {
		key  SettingKey
		name string
	}{
		{KeyAlertErrorRate, "错误率告警阈值"},
		{KeyAlertDisk, "磁盘告警阈值"},
	} {
		n, err := strconv.Atoi(strings.TrimSpace(view(item.key)))
		if err != nil || n < 0 || n > 100 {
			return fmt.Errorf("%w: %s需为 0-100 的整数百分比（0 表示关闭该项检查）", ErrInvalidParam, item.name)
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(view(KeyAlertBackupHours))); err != nil || n < 0 || n > 8760 {
		return fmt.Errorf("%w: 备份超时告警需为 0-8760 的整数小时（0 表示关闭该项检查）", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(view(KeyAlertSustained))); err != nil || n < 1 || n > 12 {
		return fmt.Errorf("%w: 持续判定需为 1-12 个采样窗口（每窗口 5 分钟，1 表示立即触发）", ErrInvalidParam)
	}
	if raw := strings.TrimSpace(view(KeyAlertSilenceUntil)); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return fmt.Errorf("%w: 静默截止时间需为 RFC3339 时间（如 2026-10-20T23:00:00+08:00）", ErrInvalidParam)
		}
		if t.After(time.Now().AddDate(1, 0, 0)) {
			return fmt.Errorf("%w: 静默截止时间不要超过一年：长期静默等于把告警关掉却不留痕迹", ErrInvalidParam)
		}
	}
	if n := len([]rune(strings.TrimSpace(view(KeyAlertSilenceReason)))); n > 200 {
		return fmt.Errorf("%w: 静默原因不能超过 200 字", ErrInvalidParam)
	}
	return nil
}

func validateOAuthSettings(view func(SettingKey) string, truthy func(SettingKey) bool) error {
	type pair struct {
		name       string
		enabled    SettingKey
		clientID   SettingKey
		clientSecr SettingKey
	}
	for _, p := range []pair{
		{"GitHub", KeyOAuthGitHubEnabled, KeyOAuthGitHubClientID, KeyOAuthGitHubClientSecret},
		{"Google", KeyOAuthGoogleEnabled, KeyOAuthGoogleClientID, KeyOAuthGoogleClientSecret},
	} {
		if !truthy(p.enabled) {
			continue
		}
		if view(p.clientID) == "" {
			return fmt.Errorf("%w: 启用 %s 登录前请填写 Client ID", ErrInvalidParam, p.name)
		}
		secret := view(p.clientSecr)
		if secret == "" || secret == SecretMask {
			return fmt.Errorf("%w: 启用 %s 登录前请填写 Client Secret", ErrInvalidParam, p.name)
		}
		if len(secret) < 8 {
			return fmt.Errorf("%w: %s 的 Client Secret 看起来不完整", ErrInvalidParam, p.name)
		}
		if view(KeyDomainPanel) == "" {
			return fmt.Errorf("%w: 启用 %s 登录前请先填写面板域名：回调地址由它拼出，必须与平台登记的完全一致",
				ErrInvalidParam, p.name)
		}
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
