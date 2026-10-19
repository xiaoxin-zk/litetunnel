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

var ErrDomainApply = errors.New("配置下发失败")

type DomainAppliedSet struct {
	Panel     string `json:"panel"`
	Tunnel    string `json:"tunnel"`
	HTTPSMode string `json:"https_mode"`
}

func (s *Services) DomainDesired() DomainAppliedSet {
	return DomainAppliedSet{
		Panel:     s.DesiredPanelDomain(),
		Tunnel:    s.DesiredTunnelDomain(),
		HTTPSMode: s.DesiredDomainHTTPSMode(),
	}
}

func (s *Services) DomainApplied() DomainAppliedSet {
	return DomainAppliedSet{
		Panel:     normalizeDomainValue(s.UserPublicURL()),
		Tunnel:    s.TunnelDomain(),
		HTTPSMode: s.DomainHTTPSMode(),
	}
}

func (s *Services) DomainPending() bool {
	d, a := s.DomainDesired(), s.DomainApplied()
	if d.Panel != a.Panel || d.Tunnel != a.Tunnel || d.HTTPSMode != a.HTTPSMode {
		return true
	}
	return s.DomainDesiredDigest() != s.DomainAppliedDigest()
}

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

func (s *Services) DomainDesiredDigest() string {
	return domainDigest(s.domainVars(false))
}

func (s *Services) DomainAppliedDigest() string {
	if s.Settings.hasRow(KeyDomainAppliedDigest) {
		return s.Settings.Get(KeyDomainAppliedDigest)
	}
	return domainDigest(s.domainVars(true))
}

type DomainStatus struct {
	Helper           tlscfg.Health     `json:"helper"`
	HelperReason     string            `json:"helper_reason"`
	HelperConfigured bool              `json:"helper_configured"`
	Certs            tlscfg.CertStatus `json:"certs"`
	Desired          DomainAppliedSet  `json:"desired"`
	Applied          DomainAppliedSet  `json:"applied"`
	Pending          bool              `json:"pending"`
}

func (s *Services) DomainConfigVars() (map[string]string, error) {
	return s.domainConfigVars(s.DomainSnapshot())
}

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

func (s *Services) domainVars(fromEnv bool) map[string]string {
	return s.domainVarsWith(s.DomainSnapshot(), fromEnv)
}

type DomainConfigSnapshot struct {
	Panel         string
	Tunnel        string
	HTTPSMode     string
	ExpectedIP    string
	ACMEEmail     string
	DNSProvider   string
	DNSArgs       string
	DNSCredential string
	HelperAddr    string
	HelperToken   string
}

func (s *Services) DomainSnapshot() DomainConfigSnapshot {
	return s.domainSnapshotLocked()
}

func (s *Services) domainSnapshotLocked() DomainConfigSnapshot {
	vals, present := s.Settings.Snapshot(
		KeyDomainPanel, KeyDomainTunnel, KeyDomainHTTPSMode, KeyDomainExpectedIP,
		KeyDomainACMEEmail, KeyDomainDNSProvider, KeyDomainDNSArgs, KeyDomainDNSCredential,
		KeyDomainHelperAddr, KeyDomainHelperToken,
	)
	snap := DomainConfigSnapshot{
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

func (s *Services) domainVarsWith(snap DomainConfigSnapshot, fromEnv bool) map[string]string {
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
	vars[tlscfg.VarACMEEmail] = ""
	vars[tlscfg.VarDNSProvider] = ""
	vars[tlscfg.VarDNSArgs] = ""
	vars[tlscfg.VarDNSCredential] = ""
	return vars
}

func (s *Services) DesiredPanelDomain() string {
	if v := normalizeDomainValue(s.Settings.Get(KeyDomainPanel)); v != "" {
		return v
	}
	return normalizeDomainValue(s.Cfg.UserPublicURL)
}

func (s *Services) DesiredTunnelDomain() string {
	if s.Settings.hasRow(KeyDomainTunnel) {
		return normalizeDomainValue(s.Settings.Get(KeyDomainTunnel))
	}
	return normalizeDomainValue(s.Cfg.TunnelDomain)
}

func (s *Services) DesiredDomainHTTPSMode() string {
	switch strings.ToLower(strings.TrimSpace(s.Settings.Get(KeyDomainHTTPSMode))) {
	case tlscfg.HTTPSModeE2E:
		return tlscfg.HTTPSModeE2E
	case tlscfg.HTTPSModeEdge:
		return tlscfg.HTTPSModeEdge
	}
	return s.envHTTPSMode()
}

func (s *Services) DomainHTTPSMode() string {
	switch strings.ToLower(strings.TrimSpace(s.Settings.Get(KeyDomainAppliedMode))) {
	case tlscfg.HTTPSModeE2E:
		return tlscfg.HTTPSModeE2E
	case tlscfg.HTTPSModeEdge:
		return tlscfg.HTTPSModeEdge
	}
	return s.envHTTPSMode()
}

func (s *Services) envHTTPSMode() string {
	if strings.EqualFold(strings.TrimSpace(s.Cfg.HTTPSProxyMode), tlscfg.HTTPSModeE2E) {
		return tlscfg.HTTPSModeE2E
	}
	return tlscfg.HTTPSModeEdge
}

func (s *Services) TunnelDomain() string {
	if s.Settings.hasRow(KeyDomainAppliedTunnel) {
		return normalizeDomainValue(s.Settings.Get(KeyDomainAppliedTunnel))
	}
	return normalizeDomainValue(s.Cfg.TunnelDomain)
}

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

func (s *Services) markDomainApplied(vars map[string]string) error {
	mode := strings.ToLower(strings.TrimSpace(vars[tlscfg.VarHTTPSMode]))
	if mode != tlscfg.HTTPSModeE2E {
		mode = tlscfg.HTTPSModeEdge
	}
	return s.Settings.SetInternal(map[SettingKey]string{
		KeyDomainAppliedPanel:  normalizeDomainValue(vars[tlscfg.VarUserPublicURL]),
		KeyDomainAppliedTunnel: normalizeDomainValue(vars[tlscfg.VarTunnelDomain]),
		KeyDomainAppliedMode:   mode,
		KeyDomainAppliedDigest: domainDigest(vars),
	})
}

func (s *Services) HTTPSProxyEntryEnabled() bool {
	return s.DomainHTTPSMode() == tlscfg.HTTPSModeE2E && s.TunnelDomain() != ""
}

func (s *Services) HTTPSProxyEntryPort() int {
	if !s.HTTPSProxyEntryEnabled() {
		return 0
	}
	return s.Cfg.VhostHTTPSPort
}

func (s *Services) HTTPSProxyEntry() string {
	port := s.HTTPSProxyEntryPort()
	if port <= 0 || s.Cfg.GatewayHost == "" {
		return ""
	}
	return s.Cfg.GatewayHost + ":" + strconv.Itoa(port)
}

var ErrNoHTTPSProxyEntry = errors.New(
	"本站未开启端到端 HTTPS 模式，HTTPS 隧道没有公网入口：" +
		"本地网站走 HTTP 时请改用「HTTP 隧道」，由平台提供访客侧 HTTPS；" +
		"确实需要端到端加密请联系管理员在「域名与证书」里开启端到端模式")

func (s *Services) TunnelPublicAddr(t *model.Tunnel) string {
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

func (s *Services) DomainHelper() *tlscfg.Client {
	snap := s.DomainSnapshot()
	return tlscfg.NewClient(snap.HelperAddr, snap.HelperToken)
}

func (s *Services) ApplyDomainConfig(ctx context.Context, apply bool) (tlscfg.RenderResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.domainMu.Lock()
	defer s.domainMu.Unlock()

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
		Vars:     vars,
		WriteEnv: true,
		Apply:    apply,
	})
	if err != nil {
		return res, fmt.Errorf("%w: %s", ErrDomainApply, err.Error())
	}

	if apply && res.Applied {
		if err := s.markDomainApplied(vars); err != nil {
			log.Printf("[domain] 记录已生效的域名配置失败: %v", err)
		}
	}
	return res, nil
}

func (s *Services) DomainDNSCheck(ctx context.Context) ([]tlscfg.DNSRecord, error) {
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

func (s *Services) DomainStatus() DomainStatus {
	client := s.DomainHelper()
	st := DomainStatus{HelperConfigured: client.Configured()}

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

func normalizeDomainValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimRight(v, "/")
	return strings.TrimSpace(v)
}

func splitDomainPort(d string) (host, port string, err error) {
	i := strings.IndexByte(d, ':')
	if i < 0 {
		return d, "", nil
	}
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

func randomProbeLabel() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "lt-probe"
	}
	return "lt-probe-" + hex.EncodeToString(buf)
}
