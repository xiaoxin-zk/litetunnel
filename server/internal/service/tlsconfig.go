package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
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

// DomainAppliedSet 是「域名与证书」这一组里真正影响**运行期行为**的三个值。
//
// 只有这三个：ACME 邮箱、DNS 服务商/参数/凭据只影响渲染出的文件内容，
// 不参与运行期判权（按哪个域名放行、按什么模式拼地址），塞进来只会让
// 「宿主机实际在用」那一栏显示出与运行期无关的东西。
//
// 但它们仍然决定「磁盘上跑的是不是你刚保存的那一份」，所以不能因此就不管：
// 完整的下发输入由 DomainPending 用摘要比较（见 KeyDomainAppliedDigest）。
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
//
// 必须走与运行期同一套读取器（UserPublicURL / TunnelDomain / DomainHTTPSMode），
// 而不是直接读 domain.applied_*：后者在「从未用过这个页面」的部署上是空的，
// 于是 Applied 为空、Desired 是 .env 的值，Pending 会恒为真——页面一直报
// 「已保存的配置还没有生效」、并把「宿主机实际在用」显示成「未设置面板域名」，
// 而实际流量正按 .env 正常跑着。那种部署必须继续以 .env 为准。
func (s *Services) DomainApplied() DomainAppliedSet {
	return DomainAppliedSet{
		Panel:     normalizeDomainValue(s.UserPublicURL()),
		Tunnel:    s.TunnelDomain(),
		HTTPSMode: s.DomainHTTPSMode(),
	}
}

// DomainPending 表示磁盘/容器上跑的还是上一份配置。
//
// 两层判断缺一不可：
//
//	前三项（面板域名 / 隧道域名 / 模式）决定**运行期行为**，比较的是归一化后
//	的取值，差异要能直接讲给管理员听（界面上会逐项列出）；
//	摘要覆盖**全部下发输入**，包括 DNS 服务商、DNS 参数、凭据与 ACME 邮箱。
//	只保存这些字段同样需要一次下发才生效，而它们不在前三项里——不比摘要的话，
//	页面会显示「与期望一致」，磁盘上跑的却还是旧配置。
func (s *Services) DomainPending() bool {
	d, a := s.DomainDesired(), s.DomainApplied()
	if d.Panel != a.Panel || d.Tunnel != a.Tunnel || d.HTTPSMode != a.HTTPSMode {
		return true
	}
	return s.DomainDesiredDigest() != s.DomainAppliedDigest()
}

// domainDigest 对完整下发变量集取摘要。
//
// 用定长摘要而不是把值逐项存一份：变量集里有 DNS API 凭据，存明文等于把密钥
// 复制到设置表里，多一处泄漏面。摘要只用于判等，不参与渲染。
//
// 序列化必须是确定的：按 key 排序后逐对写入，并用分隔符隔开，避免
// ("ab","c") 与 ("a","bc") 拼出同一个字节串。
func domainDigest(vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(vars[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DomainDesiredDigest 是「界面上保存的那一份」的摘要。
func (s *Services) DomainDesiredDigest() string {
	return domainDigest(s.domainVars(false))
}

// DomainAppliedDigest 是「宿主机上实际生效的那一份」的摘要。
//
// 没有任何下发记录时取 .env 基线：那才是实际在跑的配置，而不是「还没生效的
// 期望值」。与 DomainApplied 用同一套回落口径，否则从未进过后台的部署会被
// 判成「待下发」。
func (s *Services) DomainAppliedDigest() string {
	if s.Settings.hasRow(KeyDomainAppliedDigest) {
		return s.Settings.Get(KeyDomainAppliedDigest)
	}
	return domainDigest(s.domainVars(true))
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
	return s.domainConfigVars(s.DomainSnapshot())
}

// domainConfigVars 用同一份快照做校验与变量组装。
func (s *Services) domainConfigVars(snap DomainConfigSnapshot) (map[string]string, error) {
	if snap.Panel == "" {
		return nil, fmt.Errorf("%w: 请先填写面板域名（HTTP 模式可填域名或公网 IP）", ErrInvalidParam)
	}
	if err := checkPanelDomain(snap.Panel); err != nil {
		return nil, fmt.Errorf("%w: 面板域名 %s", ErrInvalidParam, err.Error())
	}
	if snap.Tunnel != "" {
		if err := checkDomain(snap.Tunnel); err != nil {
			return nil, fmt.Errorf("%w: 隧道域名 %s", ErrInvalidParam, err.Error())
		}
	}
	return s.domainVarsWith(snap, false), nil
}

// domainVars 组装一次下发的**完整**变量集：helper 渲染 Caddyfile 与 frps.toml
// 的全部输入都在这里。摘要比较也用同一个函数，两处必须同源——各写一份的话，
// 漏掉的字段恰好就是「待下发」判不出来的那些。
//
// fromEnv 为 true 时取「.env 基线」：域名与模式来自面板启动时的环境变量，
// 渲染类字段取空。它代表从未下发过的部署**实际在跑**的那一份（手工部署时
// 域名就写在 .env 里），用来与期望值做同口径比较。
func (s *Services) domainVars(fromEnv bool) map[string]string {
	return s.domainVarsWith(s.DomainSnapshot(), fromEnv)
}

// DomainConfigSnapshot 是一次读取得到的域名相关配置。
//
// 为什么要快照：DNS 检查、变量校验与下发各自要读域名、模式、helper 地址与
// 令牌、期望 IP、DNS 凭据等 6~9 个键。逐个读的话，两个请求交错时可能拿到
// 「旧域名 + 新凭据」这种从未存在过的组合，检查结论也就没有意义。
type DomainConfigSnapshot struct {
	Panel          string
	Tunnel         string
	HTTPSMode      string
	ExpectedIP     string
	ACMEEmail      string
	DNSProvider    string
	DNSArgs        string
	DNSCredential  string
	HelperAddr     string
	HelperToken    string
}

// DomainSnapshot 取一份域名配置快照。
//
// 原子性由 SettingStore.Snapshot 的读锁保证（一次读出所有相关键），刻意
// **不**占 domainMu：那把锁在整次下发期间持有（可能几分钟），状态页若为
// 读一次配置去等它，会一直转圈。domainMu 只负责把「读—渲染—标记已生效」
// 串成一个整体，跨请求的配置一致性靠 Settings 自己的原子读。
func (s *Services) DomainSnapshot() DomainConfigSnapshot {
	return s.domainSnapshotLocked()
}

// domainSnapshotLocked 读取快照；调用方必须已持有 domainMu。
func (s *Services) domainSnapshotLocked() DomainConfigSnapshot {
	vals, present := s.Settings.Snapshot(
		KeyDomainPanel, KeyDomainTunnel, KeyDomainHTTPSMode, KeyDomainExpectedIP,
		KeyDomainACMEEmail, KeyDomainDNSProvider, KeyDomainDNSArgs, KeyDomainDNSCredential,
		KeyDomainHelperAddr, KeyDomainHelperToken,
	)
	snap := DomainConfigSnapshot{
		// 面板域名不允许为空：空值只是异常状态，回落到 .env 比下发空域名好。
		Panel:         normalizeDomainValue(vals[KeyDomainPanel]),
		ExpectedIP:    strings.TrimSpace(vals[KeyDomainExpectedIP]),
		ACMEEmail:     strings.TrimSpace(vals[KeyDomainACMEEmail]),
		DNSProvider:   strings.TrimSpace(vals[KeyDomainDNSProvider]),
		DNSArgs:       strings.TrimSpace(vals[KeyDomainDNSArgs]),
		DNSCredential: vals[KeyDomainDNSCredential],
		HelperAddr:    vals[KeyDomainHelperAddr],
		HelperToken:   vals[KeyDomainHelperToken],
	}
	if snap.Panel == "" {
		snap.Panel = normalizeDomainValue(s.Cfg.UserPublicURL)
	}
	// 隧道域名区分「没有行」与「有行且为空」：后者是管理员明确关闭。
	if present[KeyDomainTunnel] {
		snap.Tunnel = normalizeDomainValue(vals[KeyDomainTunnel])
	} else {
		snap.Tunnel = normalizeDomainValue(s.Cfg.TunnelDomain)
	}
	switch strings.ToLower(strings.TrimSpace(vals[KeyDomainHTTPSMode])) {
	case tlscfg.HTTPSModeE2E:
		snap.HTTPSMode = tlscfg.HTTPSModeE2E
	case tlscfg.HTTPSModeEdge:
		snap.HTTPSMode = tlscfg.HTTPSModeEdge
	default:
		snap.HTTPSMode = s.envHTTPSMode()
	}
	return snap
}

// domainVarsWith 用一份快照组装下发的完整变量集。
func (s *Services) domainVarsWith(snap DomainConfigSnapshot, fromEnv bool) map[string]string {
	// 只发「面板对外地址」而不是站点地址：站点地址（LT_USER_DOMAIN）由 helper
	// 从它派生，这样「面板域名」在这一套里只有一个来源。
	//
	// 这一份是**要下发**的配置，因此取期望值而不是已生效值。
	vars := map[string]string{
		tlscfg.VarUserPublicURL: s.publicPanelURLWithScheme(snap.Panel, publicURLScheme(s.Cfg.UserPublicURL)),
		tlscfg.VarTunnelDomain:  snap.Tunnel,
		tlscfg.VarACMEEmail:     snap.ACMEEmail,
		tlscfg.VarDNSProvider:   snap.DNSProvider,
		tlscfg.VarDNSArgs:       snap.DNSArgs,
		tlscfg.VarDNSCredential: snap.DNSCredential,
		tlscfg.VarHTTPSMode:     snap.HTTPSMode,
	}
	if !fromEnv {
		return vars
	}
	vars[tlscfg.VarUserPublicURL] = s.publicPanelURLWithScheme(normalizeDomainValue(s.Cfg.UserPublicURL), publicURLScheme(s.Cfg.UserPublicURL))
	vars[tlscfg.VarTunnelDomain] = normalizeDomainValue(s.Cfg.TunnelDomain)
	vars[tlscfg.VarHTTPSMode] = s.envHTTPSMode()
	// 渲染类字段没有 .env 来源（helper 从它自己的 .env 读），面板侧的默认值就是
	// 空串；与期望值一侧「未配置」的写法一致，两边才能比较。
	vars[tlscfg.VarACMEEmail] = ""
	vars[tlscfg.VarDNSProvider] = ""
	vars[tlscfg.VarDNSArgs] = ""
	vars[tlscfg.VarDNSCredential] = ""
	return vars
}

// DesiredPanelDomain 返回界面上保存的面板域名（期望值，未必已生效）。
//
// 面板域名不能用下面隧道域名那套「行存在即用其值」的判据：它**不允许为空**
// （Caddy 要靠它签证书、找回密码邮件要靠它拼链接），空值只会是异常状态，
// 此时回落到 .env 比把一个空域名下发出去要好。
func (s *Services) DesiredPanelDomain() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainPanel)); v != "" {
		return v
	}
	return normalizeDomainValue(s.Cfg.UserPublicURL)
}

// DesiredTunnelDomain 返回界面上保存的隧道根域名（期望值，未必已生效）。
//
// 空值有两种含义，必须按「库里有没有这一行」区分，而不是按「值是否为空」：
//
//	没有行     → 从未配置过，继续以 .env 为准；
//	有行且为空 → 管理员明确关闭了 HTTP/HTTPS 隧道。
//
// 混为一谈的后果是「关闭」这个操作根本不生效：清空后保存会被当成「没配过」
// 而回落到 .env，下发给 helper 的仍然是旧域名，Caddyfile 里的泛域名站点块
// （// @if LT_TUNNEL_DOMAIN）也永远不会被剪掉。
func (s *Services) DesiredTunnelDomain() string {
	if s.Settings.hasRow(KeyDomainTunnel) {
		return normalizeDomainValue(s.Settings.Get(KeyDomainTunnel))
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
//
// 与 DesiredTunnelDomain 一样要区分「没有行」与「有行但为空」：后者是一次
// 成功的下发把隧道关掉了，运行期必须真的关掉（不再放行任何子域名隧道），
// 而不是回落到 .env 把 .env 里的旧域名又捡回来。
func (s *Services) TunnelDomain() string {
	if s.Settings.hasRow(KeyDomainAppliedTunnel) {
		return normalizeDomainValue(s.Settings.Get(KeyDomainAppliedTunnel))
	}
	return normalizeDomainValue(s.Cfg.TunnelDomain)
}

// UserPublicURL 返回面板对外地址（带 scheme），同样以**已下发**的为准。
func (s *Services) UserPublicURL() string {
	if v := strings.TrimSpace(s.Settings.Get(KeyDomainAppliedPanel)); v != "" {
		return s.publicPanelURLWithScheme(v, s.desiredPanelScheme())
	}
	return normalizePublicURL(s.Cfg.UserPublicURL)
}

func (s *Services) desiredPanelScheme() string {
	return publicURLScheme(s.Cfg.UserPublicURL)
}

func publicURLScheme(raw string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "http://") {
		return "http"
	}
	return "https"
}

func (s *Services) publicPanelURLWithScheme(domain, scheme string) string {
	if scheme != "http" {
		scheme = "https"
	}
	return scheme + "://" + normalizeDomainValue(domain)
}

func normalizePublicURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
		return raw
	}
	if raw == "" {
		return ""
	}
	return "https://" + raw
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
		// 摘要与前三项一起提交：它们描述的是同一次下发的结果，分开写会出现
		// 「域名已生效、摘要还是上一份」的中间态，页面据此误报「待下发」。
		KeyDomainAppliedDigest: domainDigest(vars),
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
	// 走同一份快照：地址与令牌必须成对读取，逐个 Get 可能拼出
	// 「旧地址 + 新令牌」的组合，表现为 401 或连到错误实例。
	snap := s.DomainSnapshot()
	return tlscfg.NewClient(snap.HelperAddr, snap.HelperToken)
}

// ApplyDomainConfig 把当前设置渲染成 Caddyfile / frps.toml 并（可选）应用。
//
// 这里刻意不接受任何参数来覆盖配置：面板是配置的唯一权威来源，
// 而 helper 只认白名单内的键。否则「界面上保存的」与「实际生效的」
// 会立刻分叉，而这套部署里最难的排查就是「两份配置不一样」。
//
// 全程持有 domainMu：从读取变量、调 helper 到记录「已生效」是一整个临界区
// （为什么必须整个流程一起锁，见 service.go 里 domainMu 的说明）。helper
// 那边也有自己的互斥，但这只保证单次渲染原子；保证不了两次下发的先后
// 与「已生效」标记的先后一致。
func (s *Services) ApplyDomainConfig(ctx context.Context, apply bool) (tlscfg.RenderResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.domainMu.Lock()
	defer s.domainMu.Unlock()

	// 整个下发过程用同一份快照：helper 地址/令牌与要渲染的变量必须来自
	// 同一次读取。分两次读会出现「发给 A helper 的却是给 B 的配置」。
	snap := s.domainSnapshotLocked()
	client := tlscfg.NewClient(snap.HelperAddr, snap.HelperToken)
	if !client.Configured() {
		return tlscfg.RenderResult{}, fmt.Errorf("%w: %s", ErrDomainApply, client.Reason())
	}
	vars, err := s.domainConfigVars(snap)
	if err != nil {
		return tlscfg.RenderResult{}, err
	}

	res, err := client.Render(ctx, tlscfg.RenderRequest{
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
// ctx 是发起检查的请求上下文：DNS 检查串行跑若干条记录，单条 5 秒，
// 最多 20 条。客户端断开后必须尽快收手，否则重复点击会叠出成堆的后台查询。
func (s *Services) DomainDNSCheck(ctx context.Context) ([]tlscfg.DNSRecord, error) {
	// 一次快照读全：域名、期望 IP、helper 地址与令牌必须同源。逐个读会在
	// 并发保存时混用新旧配置（用旧域名配新凭据去查，结论没有意义）。
	snap := s.DomainSnapshot()
	client := tlscfg.NewClient(snap.HelperAddr, snap.HelperToken)
	if !client.Configured() {
		return nil, fmt.Errorf("%w: %s", ErrDomainApply, client.Reason())
	}

	names := make([]string, 0, 3)
	if snap.Panel != "" {
		names = append(names, snap.Panel)
	}
	if snap.Tunnel != "" {
		names = append(names, snap.Tunnel)
		names = append(names, randomProbeLabel()+"."+snap.Tunnel)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: 请先填写面板域名与隧道根域名", ErrInvalidParam)
	}

	return client.DNSCheck(ctx, tlscfg.DNSCheckRequest{
		Names:      names,
		ExpectedIP: snap.ExpectedIP,
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

// splitDomainPort 把 "host[:port]" 拆成主机与端口两部分。
//
// 面板域名常常直接来自 LT_USER_PUBLIC_URL，而后者是**对外访问地址**：直连部署
// 写成 http://203.0.113.10:7848 是常态。若把冒号一并判为非法，派生出来的默认
// 值就永远过不了自己的校验——后台保存任何设置（改个 SMTP 端口）都会被
// 「面板域名不合法（含有非法字符 ":"）」顶回来。
func splitDomainPort(d string) (host, port string, err error) {
	i := strings.IndexByte(d, ':')
	if i < 0 {
		return d, "", nil
	}
	// 多个冒号只可能是 IPv6 字面量。这一套链路（Caddy 站点地址、证书签发、
	// 域名段校验）都不支持它，明确拒绝比给出一个含混的错误好。
	if strings.Count(d, ":") > 1 {
		return "", "", fmt.Errorf("含有非法字符 %q（IPv6 地址暂不支持，请改用域名或 IPv4）", ":")
	}
	host, port = d[:i], d[i+1:]
	if host == "" {
		return "", "", fmt.Errorf("缺少主机部分")
	}
	if port == "" {
		return "", "", fmt.Errorf("端口不能为空")
	}
	return host, port, nil
}

// checkPanelDomain 校验面板域名：允许 host[:port]。
//
// 端口在这里是合法的：Caddy 站点地址本身就支持 [scheme://]host[:port]，
// 对外地址带端口时下发的就是带端口的站点地址。隧道根域名不走这里——子域名
// 转发由 Caddy 按域名匹配，端口没有意义。
func checkPanelDomain(d string) error {
	host, port, err := splitDomainPort(d)
	if err != nil {
		return err
	}
	if err := checkDomain(host); err != nil {
		return err
	}
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("端口 %q 不合法（需 1-65535 的整数）", port)
	}
	return nil
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
	if len(d) > 253 {
		return fmt.Errorf("域名总长度不能超过 253 个字符（当前 %d）", len(d))
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("存在空的域名段")
		}
		// 单个标签最长 63：超过之后 DNS 与证书签发都会失败，
		// 而失败发生在申请证书阶段，错误信息与「域名太长」毫无关联。
		if len(l) > 63 {
			return fmt.Errorf("域名段 %q 超过 63 个字符", l)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("域名段 %q 不能以 - 开头或结尾", l)
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
