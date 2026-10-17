package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// UpdateSettings 校验后写入运行期配置。
//
// 校验基于「当前值 + 本次提交」的合并视图，因此可以跨字段判断
// （例如：只提交了开关、SMTP 参数沿用旧值时也能正确判断参数是否齐全）。
func (s *Services) UpdateSettings(in map[SettingKey]string) error {
	// 本次提交改了「域名与证书」这一组时，与下发流程互斥（domainMu）：
	// 下发是逐个 key 读设置再渲染，读到一半插进一次保存，会把
	// 「从未作为整体保存过」的组合原样下发并记为已生效。
	//
	// 只在这一组**确实被改**时才取锁：下发可能持续数分钟，
	// 不能让改个公告的普通保存排在它后面。
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

	// ---- 邮件 ----
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

	// ---- 支付 ----
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

	// ---- 端口 ----
	if ports := ParsePortList(view(KeyFirewallProtected)); len(ports) == 0 {
		return fmt.Errorf("%w: 保护端口列表不能为空，否则面板可能把自己锁在门外", ErrInvalidParam)
	}
	// 保护端口必须覆盖面板自身的监听端口，这是最后一道保险。
	if _, panelPort, err := splitHostPortLoose(s.Cfg.UserAddr); err == nil && panelPort != "" {
		if p, err := strconv.Atoi(panelPort); err == nil {
			if !ParsePortList(view(KeyFirewallProtected))[p] {
				return fmt.Errorf("%w: 保护端口必须包含控制面自身端口 %d", ErrInvalidParam, p)
			}
		}
	}

	// ---- 防火墙 ----
	//
	// 启用前必须配好 helper。不校验的话，表现会是「开关打开了但没有任何
	// 效果」——管理员只能靠翻容器日志才知道 helper 没配。
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

	// ---- 注册 ----
	if n, err := strconv.Atoi(view(KeyRegisterMaxPerIP)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单 IP 每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyRegisterMaxPerDomain)); err != nil || n < 0 || n > 1000 {
		return fmt.Errorf("%w: 单域名每日注册上限需为 0-1000 的整数", ErrInvalidParam)
	}

	allowDomains := ParseDomainList(view(KeyRegisterAllowDomains))
	blockDomains := ParseDomainList(view(KeyRegisterBlockDomains))
	for d := range allowDomains {
		if blockDomains[d] {
			return fmt.Errorf("%w: 域名 %s 同时出现在白名单与黑名单中，行为不可预期", ErrInvalidParam, d)
		}
	}
	if truthy(KeyRegisterWhitelistOnly) && len(allowDomains) == 0 {
		return fmt.Errorf("%w: 选择「仅允许白名单域名注册」时必须先填写白名单", ErrInvalidParam)
	}

	// ---- 接口限流 ----
	if n, err := strconv.Atoi(view(KeyAPIRatePerMinute)); err != nil || n < 1 || n > 100000 {
		return fmt.Errorf("%w: 接口每分钟请求上限需为 1-100000 的整数", ErrInvalidParam)
	}
	if n, err := strconv.Atoi(view(KeyAPIRateBurst)); err != nil || n < 1 || n > 10000 {
		return fmt.Errorf("%w: 接口突发容量需为 1-10000 的整数", ErrInvalidParam)
	}

	// ---- 域名与证书 ----
	if err := validateDomainSettings(view, s.Settings.Get); err != nil {
		return err
	}

	// 记下改动前的防火墙开关：如果这次把它打开了，要立刻唤醒协调器，
	// 让它马上做一次规则对齐并开始重试待办，而不是等下一个轮询周期。
	firewallWasOn := s.Settings.Bool(KeyFirewallEnabled)

	if err := s.Settings.SetMany(in); err != nil {
		return err
	}

	if _, changed := in[KeyFirewallEnabled]; changed && !firewallWasOn && s.Settings.Bool(KeyFirewallEnabled) {
		s.KickFirewall()
	}
	return nil
}

// validateDomainSettings 校验「域名与证书」这一组。
//
// 只做面板自己就能判定的检查（域名格式、字段之间的依赖关系）；「这份配置
// Caddy 到底能不能加载」必须在宿主机上用**目标镜像**验证，那是 helper 的
// 职责（见 cmd/lt-config 的 validateCaddy）。
//
// 校验范围的取舍：域名本来就为空时直接放过。否则任何一次「改 SMTP 端口」
// 的保存都会因为「面板域名为空」而失败——把一个功能的未配置状态
// 扩散成整个设置页不可用。
func validateDomainSettings(view, current func(SettingKey) string) error {
	panel := normalizeDomainValue(view(KeyDomainPanel))
	if panel == "" {
		// 「本来就是空的」与「被清空了」必须分开处理。
		//
		// 前者是「域名还没配」的部署（开发环境、刚拉起还没填 .env），
		// 此时把整个设置页的保存一起堵死，等于让一个功能的未配置状态
		// 变成全站不可用；后者才是真正需要拦下的操作——Caddy 没有域名
		// 就签不出证书，找回密码的链接也无从拼起。
		if current(KeyDomainPanel) != "" {
			return fmt.Errorf("%w: 面板域名不能为空：Caddy 需要它签发证书，找回密码邮件也要用它拼链接", ErrInvalidParam)
		}
		return nil
	}
	if err := checkDomain(panel); err != nil {
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
		// 泛域名证书只能走 DNS Challenge：没有 dns 指令就签不出证书，
		// 缺的不是「一项配置」，而是整个 HTTP/HTTPS 隧道入口。
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

	if addr := strings.TrimSpace(view(KeyDomainHelperAddr)); addr != "" && !strings.HasPrefix(addr, "http") {
		return fmt.Errorf("%w: 配置服务地址需形如 http://127.0.0.1:7850", ErrInvalidParam)
	}
	if token := view(KeyDomainHelperToken); token != "" && len(token) < 16 {
		return fmt.Errorf("%w: 配置服务访问令牌至少 16 个字符，否则本机任意进程都能让它重写 TLS 配置并重启容器", ErrInvalidParam)
	}
	return nil
}

// domainSettingKeys 是「域名与证书」里参与渲染下发的键，与 domainVars 同源。
//
// 以此判断一次保存要不要与下发互斥。helper 地址与令牌不在其中：
// 它们决定「找哪个 helper」，不进 Caddyfile / frps.toml，也不进已生效的
// 摘要——保存它们与一次进行中的下发交错，不会产生「从未保存过的组合」。
var domainSettingKeys = []SettingKey{
	KeyDomainPanel,
	KeyDomainTunnel,
	KeyDomainACMEEmail,
	KeyDomainDNSProvider,
	KeyDomainDNSArgs,
	KeyDomainDNSCredential,
	KeyDomainHTTPSMode,
}

// touchesDomainSettings 报告一次设置提交是否改动了「域名与证书」的渲染输入。
func touchesDomainSettings(in map[SettingKey]string) bool {
	for _, k := range domainSettingKeys {
		if _, ok := in[k]; ok {
			return true
		}
	}
	return false
}
