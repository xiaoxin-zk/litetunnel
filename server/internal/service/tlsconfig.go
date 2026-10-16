package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// ErrDomainApply 表示域名与证书配置的下发链路失败。
//
// 与 ErrInvalidParam 分开：后者是「你填错了」（面板侧就能判定），
// 前者是「配置没问题，但宿主机那一步没成」（渲染/校验/写盘/重启）。
// 两者的处置方式完全不同，混在一起只会让管理员去改本来正确的字段。
var ErrDomainApply = errors.New("配置下发失败")

// DomainAppliedSet 是「域名与证书」这一组里真正影响运行期的三个值。
//
// 只有这三个：其余项（ACME 邮箱、DNS 服务商与凭据）只影响渲染出的文件内容，
// 不影响面板按什么域名放行、按什么模式拼地址。把它们也纳入比较，只会让
// 「待下发」在无关改动上也亮起来。
type DomainAppliedSet struct {
	Panel     string `json:"panel"`
	Tunnel    string `json:"tunnel"`
	HTTPSMode string `json:"https_mode"`
}

// DomainDesired 返回界面上的**期望值**快照。
func (s *Services) DomainDesired() DomainAppliedSet {
	return DomainAppliedSet{
		Panel:     s.DesiredPanelDomain(),
		Tunnel:    s.DesiredTunnelDomain(),
		HTTPSMode: s.DesiredDomainHTTPSMode(),
	}
}

// DomainApplied 返回**已生效**的配置快照。
//
// 没有任何一次成功下发时回落到环境变量：那正是当前在跑的配置（手工部署
// 时由 .env 决定），而不是「还没生效的期望值」。
func (s *Services) DomainApplied() DomainAppliedSet {
	return DomainAppliedSet{
		Panel:     normalizeDomainValue(s.Settings.Get(KeyDomainAppliedPanel)),
		Tunnel:    normalizeDomainValue(s.Settings.Get(KeyDomainAppliedTunnel)),
		HTTPSMode: s.DomainHTTPSMode(),
	}
}

// DomainPending 表示磁盘/容器上跑的还是上一份配置。
func (s *Services) DomainPending() bool {
	d, a := s.DomainDesired(), s.DomainApplied()
	return d.Panel != a.Panel || d.Tunnel != a.Tunnel || d.HTTPSMode != a.HTTPSMode
}

// DomainStatus 是「域名与证书」页的状态总览。
type DomainStatus struct {
	// Helper 是宿主机配置服务的健康状态。
	Helper tlscfg.Health `json:"helper"`
	// HelperReason 在不可用时给出直接可读的原因。
	HelperReason string `json:"helper_reason"`
	// HelperConfigured 表示面板侧是否配齐了地址与令牌。
	HelperConfigured bool `json:"helper_configured"`
	// Certs 是 Caddy 证书存储里的证书（读不到时为空并有 reason）。
	Certs tlscfg.CertStatus `json:"certs"`
	// Desired 是界面上保存的期望配置。
	Desired DomainAppliedSet `json:"desired"`
	// Applied 是宿主机上**已经生效**的那一份。
	//
	// 与 Desired 分开是这一页存在的意义：保存只写数据库，生效要等 helper
	// 渲染、校验、写盘并重建容器。只顾着看期望值的话，「只保存未下发」与
	// 「下发失败」都会表现成「界面说已经改了」，而实际流量还走在旧配置上。
	Applied DomainAppliedSet `json:"applied"`
	// Pending 为真表示两者不一致：还需要一次「保存并应用」。
	Pending bool `json:"pending"`
}

// DomainConfigVars 组装交给 helper 的模板变量。
//
// 只发「域名与证书」这一组：其余模板变量（frps token、端口池、面板端口）
// 一律由 helper 从部署目录的 .env 读取。面板不该、也无法改它们——
// helper 的白名单会直接拒绝。
func (s *Services) DomainConfigVars() (map[string]string, error) {
	panel := s.DesiredPanelDomain()
	if panel == "" {
		return nil, fmt.Errorf("%w: 请先填写面板域名，Caddy 需要一个域名来签发证书", ErrInvalidParam)
	}
	if err := checkDomain(panel); err != nil {
		return nil, fmt.Errorf("%w: 面板域名 %s", ErrInvalidParam, err.Error())
	}
	// 只发「面板对外地址」而不是站点地址：站点地址（LT_USER_DOMAIN）由 helper
	// 从它派生，这样「面板域名」在这一套里只有一个来源。
	//
	// 这一份是**要下发**的配置，因此取期望值而不是已生效值。
	vars := map[string]string{
		tlscfg.VarUserPublicURL: "https://" + panel,
		tlscfg.VarTunnelDomain:  s.DesiredTunnelDomain(),
		tlscfg.VarACMEEmail:     strings.TrimSpace(s.Settings.Get(KeyDomainACMEEmail)),
		tlscfg.VarDNSProvider:   strings.TrimSpace(s.Settings.Get(KeyDomainDNSProvider)),
		tlscfg.VarDNSArgs:       strings.TrimSpace(s.Settings.Get(KeyDomainDNSArgs)),
		tlscfg.VarDNSCredential: s.Settings.Get(KeyDomainDNSCredential),
		tlscfg.VarHTTPSMode:     s.DesiredDomainHTTPSMode(),
	}
	return vars, nil
}

// DesiredPanelDomain 返回界面上保存的面板域名（期望值，未必已生效）。
func (s *Services) DesiredPanelDomain() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainPanel)); v != "" {
		return v
	}
	return normalizeDomainValue(s.Cfg.UserPublicURL)
}

// DesiredTunnelDomain 返回界面上保存的隧道根域名（期望值，未必已生效）。
func (s *Services) DesiredTunnelDomain() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainTunnel)); v != "" {
		return v
	}
	return normalizeDomainValue(s.Cfg.TunnelDomain)
}

// DesiredDomainHTTPSMode 返回界面上保存的 HTTPS 隧道模式（期望值）。
//
// 与 DomainHTTPSMode 的分工必须分清：这一个用于「要下发什么」，
// 那一个用于「现在实际跑的是什么」。
func (s *Services) DesiredDomainHTTPSMode() string {
	switch strings.ToLower(strings.TrimSpace(s.Settings.Get(KeyDomainHTTPSMode))) {
	case tlscfg.HTTPSModeE2E:
		return tlscfg.HTTPSModeE2E
	case tlscfg.HTTPSModeEdge:
		return tlscfg.HTTPSModeEdge
	}
	return s.envHTTPSMode()
}

// DomainHTTPSMode 返回**当前生效**的 HTTPS 隧道模式。
//
// 以「已下发」的记录为准，没有记录时回落到 .env（那才是实际在跑的配置）。
// 直接读数据库里的期望值会让「只保存未下发」立刻改变运行期行为——面板开始
// 按新模式放行或拒绝 HTTPS 隧道，而 frps 还是上一份配置。见 setting.go 里
// 已生效那一组字段的说明。
func (s *Services) DomainHTTPSMode() string {
	switch strings.ToLower(strings.TrimSpace(s.Settings.Get(KeyDomainAppliedMode))) {
	case tlscfg.HTTPSModeE2E:
		return tlscfg.HTTPSModeE2E
	case tlscfg.HTTPSModeEdge:
		return tlscfg.HTTPSModeEdge
	}
	return s.envHTTPSMode()
}

// envHTTPSMode 是没有任何下发记录时的回落值：面板启动时读到的 .env。
func (s *Services) envHTTPSMode() string {
	if strings.EqualFold(strings.TrimSpace(s.Cfg.HTTPSProxyMode), tlscfg.HTTPSModeE2E) {
		return tlscfg.HTTPSModeE2E
	}
	return tlscfg.HTTPSModeEdge
}

// TunnelDomain 返回**当前生效**的隧道根域名。
//
// 两处都不能想当然，各自对应一类事故：
//
//	不能用 Cfg.TunnelDomain：它来自面板**启动时**的环境变量，而管理端改完
//	域名后 helper 只重建 caddy 与 frps，面板容器不会重启。照 Cfg 取值会让
//	面板按旧域名放行子域名、拼出旧域名的地址。
//	也不能用数据库里的期望值：保存与下发是两步，「只保存未下发」或「下发
//	失败」时新域名还没生效，按它放行只会得到一条打不开的隧道。
//
// 所以取「已下发」的记录，没有记录时回落到 .env——那才是实际在跑的配置。
func (s *Services) TunnelDomain() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainAppliedTunnel)); v != "" {
		return v
	}
	return normalizeDomainValue(s.Cfg.TunnelDomain)
}

// UserPublicURL 返回面板对外地址（带 scheme），同样以**已下发**的为准。
func (s *Services) UserPublicURL() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainAppliedPanel)); v != "" {
		return "https://" + v
	}
	return strings.TrimRight(strings.TrimSpace(s.Cfg.UserPublicURL), "/")
}

// markDomainApplied 记录「刚下发的这一份已经在宿主机上生效」。
//
// 用刚下发的 vars 而不是重新读设置：两者之间管理员若又保存了一次，
// 记下来的就会是那份**没有下发**的值，等于把刚修好的问题重新引入。
func (s *Services) markDomainApplied(vars map[string]string) error {
	mode := strings.ToLower(strings.TrimSpace(vars[tlscfg.VarHTTPSMode]))
	if mode != tlscfg.HTTPSModeE2E {
		mode = tlscfg.HTTPSModeEdge
	}
	return s.Settings.SetInternal(map[SettingKey]string{
		KeyDomainAppliedPanel:  normalizeDomainValue(vars[tlscfg.VarUserPublicURL]),
		KeyDomainAppliedTunnel: normalizeDomainValue(vars[tlscfg.VarTunnelDomain]),
		KeyDomainAppliedMode:   mode,
	})
}

// HTTPSProxyEntryEnabled 表示平台当前是否为 HTTPS 隧道提供了公网入口。
//
// 只有端到端模式（e2e）才有：证书留在本地网站，frps 在独立端口上按 SNI
// 透传原始 TLS 连接。边缘模式下 443 由 Caddy 接管，它只会把请求按 HTTP
// 转发给 frps 的 HTTP vhost——此时创建的 HTTPS 隧道永远打不开，
// 所以这里返回 false 时创建接口会直接拒绝并说明原因。
func (s *Services) HTTPSProxyEntryEnabled() bool {
	return s.DomainHTTPSMode() == tlscfg.HTTPSModeE2E && s.TunnelDomain() != ""
}

// HTTPSProxyEntryPort 返回 HTTPS 隧道的公网入口端口，0 表示没有入口。
func (s *Services) HTTPSProxyEntryPort() int {
	if !s.HTTPSProxyEntryEnabled() {
		return 0
	}
	return s.Cfg.VhostHTTPSPort
}

// HTTPSProxyEntry 返回 HTTPS 隧道的公网入口（host:port），没有入口时为空串。
func (s *Services) HTTPSProxyEntry() string {
	port := s.HTTPSProxyEntryPort()
	if port <= 0 || s.Cfg.GatewayHost == "" {
		return ""
	}
	return s.Cfg.GatewayHost + ":" + strconv.Itoa(port)
}

// ErrNoHTTPSProxyEntry 表示平台没有 HTTPS 隧道的公网入口。
//
// 单独立一个错误而不是笼统的 ErrInvalidParam：客户端与管理端都需要把
// 「该用 HTTP 隧道 / 该去开启端到端模式」这层意思原样转达给用户，
// 提示词写在这里，就不会在三个前端里各抄一份、各写错一次。
var ErrNoHTTPSProxyEntry = errors.New(
	"本站未开启端到端 HTTPS 模式，HTTPS 隧道没有公网入口：" +
		"本地网站走 HTTP 时请改用「HTTP 隧道」，由平台提供访客侧 HTTPS；" +
		"确实需要端到端加密请联系管理员在「域名与证书」里开启端到端模式")

// TunnelPublicAddr 计算隧道的对外访问地址。
//
// HTTP 与 HTTPS 两类隧道的**入口不同**，地址必须分开算：
//
//	HTTP ：走 Caddy 的 443——Caddy 用泛域名证书终止 TLS，再以 HTTP 转发给 frps。
//	HTTPS：证书在本地网站，frps 在独立端口上按 SNI 透传，地址必须带端口；
//	       没有那条入口时返回空串，而不是给一个 443 的假地址——
//	       用户照着一个跑不通的地址去试，只会以为自己配错了。
func (s *Services) TunnelPublicAddr(t *model.Tunnel) string {
	// TCP/UDP 先处理：它们与域名无关（地址是网关 + 分配到的端口），
	// 放到下面按域名拼主机名之后就会被误判成「没有主机名 = 没有地址」。
	switch t.Type {
	case model.ProxyTypeTCP, model.ProxyTypeUDP:
		if t.RemotePort <= 0 || s.Cfg.GatewayHost == "" {
			return ""
		}
		return s.Cfg.GatewayHost + ":" + strconv.Itoa(t.RemotePort)
	case model.ProxyTypeHTTP, model.ProxyTypeHTTPS:
	default:
		return ""
	}

	host := ""
	if t.Domain != "" {
		host = t.Domain
	} else if d := s.TunnelDomain(); d != "" && t.Subdomain != "" {
		host = t.Subdomain + "." + d
	}
	if host == "" {
		return ""
	}

	switch t.Type {
	case model.ProxyTypeHTTP:
		return "https://" + host
	case model.ProxyTypeHTTPS:
		if port := s.HTTPSProxyEntryPort(); port > 0 {
			return "https://" + host + ":" + strconv.Itoa(port)
		}
		return ""
	}
	return ""
}

// DomainHelper 返回宿主机配置服务的客户端。
func (s *Services) DomainHelper() *tlscfg.Client {
	return tlscfg.NewClient(
		s.Settings.Get(KeyDomainHelperAddr),
		s.Settings.Get(KeyDomainHelperToken),
	)
}

// ApplyDomainConfig 把当前设置渲染成 Caddyfile / frps.toml 并（可选）应用。
//
// 这里刻意不接受任何参数来覆盖配置：面板是配置的唯一权威来源，
// 而 helper 只认白名单内的键。否则「界面上保存的」与「实际生效的」
// 会立刻分叉，而这套部署里最难的排查就是「两份配置不一样」。
func (s *Services) ApplyDomainConfig(apply bool) (tlscfg.RenderResult, error) {
	client := s.DomainHelper()
	if !client.Configured() {
		return tlscfg.RenderResult{}, fmt.Errorf("%w: %s", ErrDomainApply, client.Reason())
	}
	vars, err := s.DomainConfigVars()
	if err != nil {
		return tlscfg.RenderResult{}, err
	}

	res, err := client.Render(tlscfg.RenderRequest{
		Vars: vars,
		// 凭据必须写回 .env：docker-compose 靠它把 DNS API 凭据注入容器，
		// 而 Caddyfile 里写的是 {env.LT_CADDY_DNS_CREDENTIAL}。
		WriteEnv: true,
		Apply:    apply,
	})
	if err != nil {
		return res, fmt.Errorf("%w: %s", ErrDomainApply, err.Error())
	}

	// 只有真的重建了容器才更新「已生效」记录：helper 报错、或者本轮只渲染
	// 不应用（apply=false），磁盘与容器都还是上一份配置。
	if apply && res.Applied {
		if err := s.markDomainApplied(vars); err != nil {
			// 配置本身已经生效，只是没能记下来：此时界面会显示「待下发」，
			// 再点一次下发即可收敛。为了这个把整次调用判为失败，
			// 反而会让管理员以为「没生效」而反复重试。
			log.Printf("[domain] 记录已生效的域名配置失败: %v", err)
		}
	}
	return res, nil
}

// DomainDNSCheck 检查与证书相关的域名解析。
//
// 除了面板域名与隧道根域名，还会探测一个**随机子域**：
// 泛域名证书签发的第一步就是服务商侧必须存在一条泛解析记录，
// 这条探测能直接把「忘了加 *.tunnel 的记录」变成一个明确结论。
func (s *Services) DomainDNSCheck() ([]tlscfg.DNSRecord, error) {
	client := s.DomainHelper()
	if !client.Configured() {
		return nil, fmt.Errorf("%w: %s", ErrDomainApply, client.Reason())
	}

	names := make([]string, 0, 3)
	if d := normalizeDomainValue(s.Settings.Get(KeyDomainPanel)); d != "" {
		names = append(names, d)
	}
	if d := normalizeDomainValue(s.Settings.Get(KeyDomainTunnel)); d != "" {
		names = append(names, d)
		names = append(names, randomProbeLabel()+"."+d)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: 请先填写面板域名与隧道根域名", ErrInvalidParam)
	}

	return client.DNSCheck(tlscfg.DNSCheckRequest{
		Names:      names,
		ExpectedIP: strings.TrimSpace(s.Settings.Get(KeyDomainExpectedIP)),
	})
}

// DomainCerts 读取 Caddy 的证书状态。
func (s *Services) DomainCerts() (tlscfg.CertStatus, error) {
	client := s.DomainHelper()
	if !client.Configured() {
		return tlscfg.CertStatus{Reason: client.Reason()}, nil
	}
	certs, err := client.Certs()
	if err != nil {
		return tlscfg.CertStatus{Reason: err.Error()}, nil
	}
	return certs, nil
}

// DomainStatus 汇总页面需要的状态：helper 健康度 + 证书 + 期望/已生效的差异。
func (s *Services) DomainStatus() DomainStatus {
	client := s.DomainHelper()
	st := DomainStatus{HelperConfigured: client.Configured()}

	// 期望与已生效的对比必须**无条件**返回，包括 helper 连不上的时候：
	// 「配了 helper 但连不上」正是最容易出现「保存了却没生效」的场景。
	st.Desired = s.DomainDesired()
	st.Applied = s.DomainApplied()
	st.Pending = s.DomainPending()

	if !client.Configured() {
		st.HelperReason = client.Reason()
		return st
	}

	h, err := client.Health()
	st.Helper = h
	if err != nil {
		st.HelperReason = fmt.Sprintf("无法连接宿主机配置服务（%s）：%v", s.Settings.Get(KeyDomainHelperAddr), err)
		return st
	}
	if !h.Available {
		st.HelperReason = h.Reason
		return st
	}

	if certs, err := s.DomainCerts(); err == nil {
		st.Certs = certs
	} else {
		st.Certs = tlscfg.CertStatus{Reason: err.Error()}
	}
	return st
}

// normalizeDomainValue 归一化用户填写的域名：去 scheme、去路径、去空白、转小写。
//
// 容忍这些是为了不让人在「https://panel.example.com/」这种写法上卡住，
// 但结果会被写进配置文件，因此归一化之后必须再走一次 checkDomain。
func normalizeDomainValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimRight(v, "/")
	return strings.TrimSpace(v)
}

// checkDomain 校验裸域名。规则与宿主机 helper 保持一致（见 cmd/lt-config）。
func checkDomain(d string) error {
	if d == "" {
		return fmt.Errorf("不能为空")
	}
	if strings.ContainsAny(d, " \t\r\n/\\*") {
		return fmt.Errorf("含有非法字符（只填裸域名，不带 scheme、路径或 *）")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("不是完整域名（至少需要两段，如 panel.example.com）")
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("存在空的域名段")
		}
		for _, r := range l {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("含有非法字符 %q", string(r))
		}
	}
	return nil
}

// randomProbeLabel 生成一个随机子域标签，用于探测泛解析。
func randomProbeLabel() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		// 读随机数失败极罕见，此时退化为固定前缀：
		// 探测结果的准确性略有下降，但功能不能因此中断。
		return "lt-probe"
	}
	return "lt-probe-" + hex.EncodeToString(buf)
}
