package tlscfg

import "strings"

const (
	VarUserPublicURL = "LT_USER_PUBLIC_URL"
	VarPanelDomain   = "LT_USER_DOMAIN"
	VarPanelScheme   = "LT_USER_SCHEME"
	VarHSTSOn        = "LT_HSTS_ON"
	VarTunnelDomain  = "LT_TUNNEL_DOMAIN"
	VarACMEEmail     = "LT_ACME_EMAIL"
	VarDNSProvider   = "LT_CADDY_DNS_PROVIDER"
	VarDNSArgs       = "LT_CADDY_DNS_ARGS"
	VarDNSCredential = "LT_CADDY_DNS_CREDENTIAL"
	VarHTTPSMode     = "LT_HTTPS_TUNNEL_MODE"
	VarHTTPSE2EPort  = "LT_HTTPS_E2E_PORT"
)

const (
	HTTPSModeEdge = "edge"
	HTTPSModeE2E  = "e2e"
)

var OverridableVars = []string{
	VarUserPublicURL,
	VarTunnelDomain,
	VarACMEEmail,
	VarDNSProvider,
	VarDNSArgs,
	VarDNSCredential,
	VarHTTPSMode,
}

var SecretVars = map[string]bool{
	VarDNSCredential: true,
}

func IsOverridable(name string) bool {
	for _, v := range OverridableVars {
		if v == name {
			return true
		}
	}
	return false
}

func HasControlChars(v string) bool {
	for _, r := range v {
		switch {
		case r < 0x20 || r == 0x7f:
			return true
		case r == '\u2028' || r == '\u2029':
			return true
		}
	}
	return false
}

func ComposeCaddyImage(envVars map[string]string) string {
	if v := strings.TrimSpace(envVars["LT_CADDY_IMAGE"]); v != "" {
		return v
	}
	return "caddy:2-alpine"
}

type Health struct {
	Available    bool   `json:"available"`
	DeployDir    string `json:"deploy_dir"`
	Docker       bool   `json:"docker"`
	DockerReady  bool   `json:"docker_ready"`
	DockerErr    string `json:"docker_err,omitempty"`
	ComposeReady bool   `json:"compose_ready"`
	ComposeErr   string `json:"compose_err,omitempty"`
	Reason       string `json:"reason"`
	Ports        Ports  `json:"ports"`

	BlockedDirs []string `json:"blocked_dirs,omitempty"`
}

type Ports struct {
	Gateway    int `json:"gateway"`
	KCP        int `json:"kcp"`
	VhostHTTP  int `json:"vhost_http"`
	VhostHTTPS int `json:"vhost_https"`
}

type RenderRequest struct {
	Vars     map[string]string `json:"vars"`
	Apply    bool              `json:"apply"`
	WriteEnv bool              `json:"write_env"`
}

type RenderResult struct {
	Applied       bool           `json:"applied"`
	Changed       []string       `json:"changed"`
	EnvUpdated    []string       `json:"env_updated"`
	Validate      string         `json:"validate"`
	Warnings      []string       `json:"warnings"`
	RequiredPorts []int          `json:"required_ports"`
	Message       string         `json:"message"`
	Partial       bool           `json:"partial,omitempty"`
	Services      []ServiceState `json:"services,omitempty"`
	ServicesError string         `json:"services_error,omitempty"`
}

type ServiceState struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type DNSCheckRequest struct {
	Names      []string `json:"names"`
	ExpectedIP string   `json:"expected_ip"`
}

type DNSRecord struct {
	Name    string   `json:"name"`
	CNAME   string   `json:"cname"`
	IPs     []string `json:"ips"`
	Matched bool     `json:"matched"`
	Error   string   `json:"error"`
	Hint    string   `json:"hint"`
}

type Certificate struct {
	Domain    string   `json:"domain"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	Kind      string   `json:"kind"`
	Names     []string `json:"names"`
}

type CertStatus struct {
	Available bool          `json:"available"`
	Reason    string        `json:"reason"`
	Certs     []Certificate `json:"certs"`
}
