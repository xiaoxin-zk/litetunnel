// Package tlscfg 承载「域名与证书」配置的渲染与下发。
//
// # 分工
//
//	控制面（internal/service）  —— 保存配置、组装模板变量、调用下面的客户端
//	宿主机 helper（cmd/lt-config）—— 渲染 Caddyfile / frps.toml、校验、写盘、重建容器
//
// # 为什么渲染不放在控制面
//
// 面板容器以 read_only 运行，只挂载了 /data：它既写不了部署目录，
// 也不持有 docker socket。让它去改 Caddy 配置，等于把「从面板打到宿主机」
// 的入口直接摆到公网上——这与防火墙写操作一律交给 lt-fw 是同一条理由
// （见 cmd/lt-fw 的包注释）。渲染留在宿主机侧，面板只负责「说要什么」。
package tlscfg

import "strings"

// 模板变量名，与 deploy/caddy/Caddyfile.template 和
// deploy/frps/frps.toml.template 里的 ${...} 占位符一一对应。
const (
	// VarUserPublicURL 是面板对外地址（带 scheme），渲染脚本由它派生站点地址。
	VarUserPublicURL = "LT_USER_PUBLIC_URL"
	// VarPanelDomain 是 Caddy 站点地址（裸域名，不带 scheme）。
	VarPanelDomain = "LT_USER_DOMAIN"
	// VarPanelScheme 是 Caddy 站点协议（http / https），由 VarUserPublicURL 派生。
	//
	// 它不放进 OverridableVars：面板只声明「对外地址」，协议是其中的一部分，
	// 单独可覆盖会造出「地址写 https、站点按 http 起」这种自相矛盾的配置。
	VarPanelScheme = "LT_USER_SCHEME"
	// VarHSTSOn 只在 HTTPS 模式下非空，模板据此决定是否发送 HSTS 头。
	//
	// HTTP 站点发送 HSTS 会让浏览器把后续请求强制升级到 https，
	// 而该站点没有证书——表现为「配好了却打不开」。
	VarHSTSOn = "LT_HSTS_ON"
	// VarTunnelDomain 是隧道根域名（裸域名，不带 *.）。
	VarTunnelDomain = "LT_TUNNEL_DOMAIN"
	// VarACMEEmail 是 ACME 通知邮箱。
	VarACMEEmail = "LT_ACME_EMAIL"
	// VarDNSProvider 是 dns 指令名，必须与镜像里编入的插件一致。
	VarDNSProvider = "LT_CADDY_DNS_PROVIDER"
	// VarDNSArgs 是传给 dns 指令的参数，默认读环境变量里的凭据。
	VarDNSArgs = "LT_CADDY_DNS_ARGS"
	// VarDNSCredential 是 DNS 服务商凭据，只经容器环境变量注入。
	VarDNSCredential = "LT_CADDY_DNS_CREDENTIAL"
	// VarHTTPSMode 是 HTTPS 隧道模式，取值见 HTTPSModeEdge / HTTPSModeE2E。
	VarHTTPSMode = "LT_HTTPS_TUNNEL_MODE"
	// VarHTTPSE2EPort 只在端到端 HTTPS 模式下非空，模板用它做条件块。
	//
	// 之所以要一个派生变量而不是直接判断 LT_HTTPS_TUNNEL_MODE：
	// 模板的条件语法只支持「非空则保留」（与渲染脚本一致），
	// 而 edge / e2e 两个取值都是非空的。
	VarHTTPSE2EPort = "LT_HTTPS_E2E_PORT"
)

// HTTPS 隧道的两种模式。
const (
	// HTTPSModeEdge：证书留在 Caddy。Caddy 用泛域名证书在 443 上终止 TLS，
	// 再以 HTTP 转发给 frps 的 vhostHTTPPort。本地网站继续用 HTTP。
	HTTPSModeEdge = "edge"
	// HTTPSModeE2E：证书留在本地网站。frps 在独立公网端口上按 SNI 转发
	// 原始 TLS 连接，Caddy 不参与——因此是真正的端到端加密。
	HTTPSModeE2E = "e2e"
)

// OverridableVars 是面板**允许**覆盖的变量白名单。
//
// helper 只接受这些键，其余一律从部署目录的 .env 读取。这条约束的意义在于：
// 即使面板被完全控制，攻击者也不能借 /render 改掉 frps token、端口池范围
// 或面板监听地址——他能动的只有「域名与证书」这一小块。
var OverridableVars = []string{
	VarUserPublicURL,
	VarTunnelDomain,
	VarACMEEmail,
	VarDNSProvider,
	VarDNSArgs,
	VarDNSCredential,
	VarHTTPSMode,
}

// SecretVars 标记「值本身是密钥」的变量。
//
// 用途有二：写回 .env 时收紧文件权限；回显与日志里一律脱敏。
var SecretVars = map[string]bool{
	VarDNSCredential: true,
}

// IsOverridable 判断某个变量是否允许由面板覆盖。
func IsOverridable(name string) bool {
	for _, v := range OverridableVars {
		if v == name {
			return true
		}
	}
	return false
}

// HasControlChars 报告字符串里是否含有控制字符（含 CR 与 LF）。
//
// 为什么这是安全判定而不是格式洁癖：这些值最终会被拼成 .env 的 key=value 行，
// 由 helper 写盘、由 Compose 读取插值。值里混进一个换行，就等于往 .env 里
// 追加整整一行——而 Compose 的插值（image: ${LT_CADDY_IMAGE:-caddy:2-alpine}）
// 接受任何来自 .env 的键。于是「面板无权覆盖 LT_CADDY_IMAGE」这条边界可以靠
// 一个换行绕过：helper 拿旧镜像校验通过，Compose 却用注入的新镜像重建。
//
// 所以两侧都拒绝而不是「过滤掉」：过滤会让人以为改动生效了，实际被悄悄改成
// 了别的值；拒绝则留下一条明确的错误。
//
// U+2028 / U+2029 一并拒绝：它们在不少工具里会被当成换行，留着只会让
// 「到底断没断行」变成一个取决于解析器的悬案。
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

// ComposeCaddyImage 返回 deploy/docker-compose.yml 实际会用来重建 caddy 的镜像。
//
// 取值口径必须与 compose 的插值逐字一致：
//
//	image: ${LT_CADDY_IMAGE:-caddy:2-alpine}
//
// 即「.env 里的 LT_CADDY_IMAGE，缺省回落到 caddy:2-alpine」。校验用的镜像
// 若不是这一个，那么「校验通过」只对另一个镜像成立——官方镜像没有 dns 插件，
// 自建镜像有，两者的指令集不同。
func ComposeCaddyImage(envVars map[string]string) string {
	if v := strings.TrimSpace(envVars["LT_CADDY_IMAGE"]); v != "" {
		return v
	}
	return "caddy:2-alpine"
}

// Health 是 helper 的健康状态。
type Health struct {
	// Available 表示 helper 可用（部署目录可写、模板存在）。
	Available bool `json:"available"`
	// DeployDir 是 helper 实际操作的部署目录，界面上直接展示，
	// 避免「面板改的那份」和「实际在跑的那份」不是同一个目录这种诡异问题。
	DeployDir string `json:"deploy_dir"`
	// Docker 表示能否调用 docker（校验与重建容器都依赖它）。
	//
	// 它只回答「docker 命令在不在」——命令在而 daemon 没起来时它仍为 true。
	// 要判断「宿主机现在能不能真的起容器」，看 DockerReady。
	Docker bool `json:"docker"`
	// DockerReady 表示 docker 命令存在**且**宿主机侧 daemon 可用（daemon
	// 可达、当前身份有权限）。
	//
	// 单独一个字段的理由：Docker 为真只能证明命令在 PATH 里。装在宿主机上
	// 但 daemon 没启动、或本服务没有 socket 权限时，它照样为真，于是面板
	// 一路放行到「保存」才在重建容器那步失败——而那时文件已经写盘了。
	//
	// 语义刻意**只**覆盖 daemon：compose 是否可用由 ComposeReady 单独报告。
	// 把 compose 折进来会让「装个插件」被界面报成「Docker 不可用」。
	DockerReady bool `json:"docker_ready"`
	// DockerErr 是 DockerReady 为假时的可读中文原因（例如命令存在但 daemon
	// 不可达），供界面直接展示；DockerReady 为真时为空。
	DockerErr string `json:"docker_err,omitempty"`
	// ComposeReady 表示 compose 可用：daemon 可用**且** `docker compose`
	// （或独立 docker-compose）能跑起来。
	//
	// 为什么在 DockerReady 之外还要一个字段：本服务重建容器只用
	// `docker compose up`（见 cmd/lt-config/compose.go），从不直接
	// `docker run`。而「daemon 能用」不等于「compose 能用」——docker 装好、
	// daemon 起来了，但 compose 插件没装（或只有 V1 的独立二进制）时，
	// `docker info` 照样成功。只看 DockerReady 的话，面板会一路放行到
	// 「保存并应用」，失败发生在文件已经写盘之后，配置与容器分处两个版本。
	//
	// 恒有 ComposeReady ⇒ DockerReady。DockerReady 的语义**不**因此改变：
	// 它仍然只回答「daemon 能不能用」，否则「装个 compose 插件」这件事
	// 会被界面报成「Docker 不可用」，把管理员引向完全错误的排查方向。
	ComposeReady bool `json:"compose_ready"`
	// ComposeErr 是 ComposeReady 为假、但 daemon 可用时的可读中文原因
	// （compose 插件与 docker-compose 都不在、或跑了不成功）。
	//
	// daemon 本身就不可用时留空：那时 ComposeReady 为假只是连带结果，
	// 多说一句「compose 不可用」只会把管理员引去装插件。界面据此在
	// 「Docker 不可用」与「compose 不可用」两种告警之间选择。
	ComposeErr string `json:"compose_err,omitempty"`
	// Reason 在不可用时说明原因，供界面直接展示。
	Reason string `json:"reason"`
	// Ports 是部署目录 .env 里那几个**与入口路由直接相关**的端口。
	//
	// 由 helper 读取而不是面板自己算：这些值（网关、KCP、vhost 入口）
	// 只在 .env 里，面板的环境变量里没有，也不该为此再存一份到数据库——
	// 两份数据一定会分叉，而分叉的表现是「界面显示的端口和实际转发的不一致」。
	Ports Ports `json:"ports"`

	// BlockedDirs 是存在「未能自动收敛的配置现场」的目录。
	//
	// 非空意味着这些目录里留着上次提交的记录与备份，helper 已经拒绝一切
	// 写盘操作（见 cmd/lt-config）。放在健康检查里而不是只在日志里说：
	// 面板是管理员唯一会主动打开的地方，否则他要等到「保存不生效」才发现。
	BlockedDirs []string `json:"blocked_dirs,omitempty"`
}

// Ports 是入口路由相关的端口。
type Ports struct {
	// Gateway 是 frpc 接入端口（TCP）。
	Gateway int `json:"gateway"`
	// KCP 是 KCP 加速端口（UDP）。
	KCP int `json:"kcp"`
	// VhostHTTP 是 HTTP 隧道入口，由 Caddy 转发进来。
	VhostHTTP int `json:"vhost_http"`
	// VhostHTTPS 是 HTTPS 隧道入口：端到端模式下它直接对公网提供，
	// 边缘模式下只对回环开放（由 Caddy 终止 TLS 后走 HTTP 入口）。
	VhostHTTPS int `json:"vhost_https"`
}

// RenderRequest 是「渲染并（可选）应用」的请求。
type RenderRequest struct {
	// Vars 只允许出现 OverridableVars 里的键；空值表示「该项留空」。
	//
	// 用「显式给出」而不是 helper 自己去读配置：面板才是配置的权威来源
	// （值存在数据库里，可加密），helper 只负责把它变成文件。
	Vars map[string]string `json:"vars"`
	// Apply 为真时，写盘后重建 caddy 与 frps 容器。
	Apply bool `json:"apply"`
	// WriteEnv 为真时，把 Vars 里的键同步写回部署目录的 .env。
	//
	// 必须要写：docker-compose 是靠 .env 插值把 DNS 凭据注入 Caddy 容器的，
	// 不写回的话 Caddyfile 里引用 {env.LT_CADDY_DNS_CREDENTIAL} 会取到空值。
	WriteEnv bool `json:"write_env"`
}

// RenderResult 是渲染与应用的结果。
type RenderResult struct {
	// Applied 表示是否真的重建了容器。
	Applied bool `json:"applied"`
	// Changed 是内容确实变化的文件清单（没变就不写、不重建）。
	Changed []string `json:"changed"`
	// EnvUpdated 是同步写回 .env 的键名（不含值，值不进日志）。
	EnvUpdated []string `json:"env_updated"`
	// Validate 是配置校验器的输出，原样回显给管理员。
	Validate string `json:"validate"`
	// Warnings 是不致命但需要管理员知道的问题。
	Warnings []string `json:"warnings"`
	// RequiredPorts 是当前配置下**必须对公网放行**的端口。
	RequiredPorts []int `json:"required_ports"`
	// Message 是给界面的一句话结论。
	Message string `json:"message"`
	// Partial 表示「磁盘与容器没能停在同一版本」。
	//
	// 典型场景：文件已换新、容器重建失败，回滚文件后又按旧配置重建也失败。
	// 这时既不能说成功，也不能说「什么都没发生」——必须让管理员知道
	// 当前是一个需要人看的状态，并配合 Services 判断先修哪一边。
	Partial bool `json:"partial,omitempty"`
	// Services 是重建失败时各 compose 容器的实际状态。
	//
	// 只有 Partial 为真时才有意义：它是「现在到底跑的是哪一版」的唯一线索。
	Services []ServiceState `json:"services,omitempty"`
}

// ServiceState 是一个 compose 服务的实际状态。
type ServiceState struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// DNSCheckRequest 是一次 DNS 检查请求。
type DNSCheckRequest struct {
	// Names 是要解析的记录名（含通配符探测用的随机子域）。
	Names []string `json:"names"`
	// ExpectedIP 非空时，逐条判断解析结果里是否包含该地址。
	ExpectedIP string `json:"expected_ip"`
}

// DNSRecord 是一条 DNS 检查结果。
type DNSRecord struct {
	Name string `json:"name"`
	// CNAME 是解析链上的别名（有就展示，「为什么 IP 对不上」多半在这里）。
	CNAME string `json:"cname"`
	// IPs 是解析出的地址，可能同时有 IPv4 与 IPv6。
	IPs []string `json:"ips"`
	// Matched 仅在请求给了 ExpectedIP 时有意义：解析结果命中该地址。
	Matched bool `json:"matched"`
	// Error 记录解析失败的原因（NXDOMAIN、超时等）。
	Error string `json:"error"`
	// Hint 是给管理员的下一步提示。
	Hint string `json:"hint"`
}

// Certificate 是 Caddy 证书存储里的一张证书。
type Certificate struct {
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
	// Kind 区分 ACME 签发（acme）与 Caddy 内部 CA（local）。
	// local 证书只在「Caddy 与本地网站之间」有意义，浏览器不认。
	Kind string `json:"kind"`
	// Names 是证书覆盖的域名（泛域名证书的 *.example.com 会在这里）。
	Names []string `json:"names"`
}

// CertStatus 是证书状态总览。
type CertStatus struct {
	Available bool          `json:"available"`
	Reason    string        `json:"reason"`
	Certs     []Certificate `json:"certs"`
}
