package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件负责「这份配置能不能用」：先看变量本身，再用**目标镜像**实际校验渲染结果。
//
// 两层的分工很重要：变量层面的检查能给出指向具体字段的错误（哪个域名不对、
// 哪个端口没填），而模板渲染与指令是否被镜像支持，只有真跑一次校验才知道。

// 传输层协议的显示名。端口冲突按「协议 + 端口号」判定：TCP 与 UDP 是彼此
// 独立的端口空间，一个 UDP 端口不会挡住同号的 TCP 监听。
const (
	protoTCP = "TCP"
	protoUDP = "UDP"
)

// portKey 把协议与端口号组成冲突判定的键。
func portKey(proto string, port int) string {
	return proto + ":" + strconv.Itoa(port)
}

// portOwner 记录某个「协议 + 端口」已被哪个变量占用，用于报出冲突双方。
type portOwner struct {
	proto string
	name  string
}

// portProtocol 声明每个端口变量监听在哪个传输层协议上。
//
// TCP 与 UDP 是两个独立的端口空间：同一个数字可以同时被两边监听。LT_KCP_PORT
// 是 KCP（UDP），其余入口与管理端口都是 TCP；80/443 固定入口也走 TCP。
var portProtocol = map[string]string{
	"LT_GATEWAY_PORT":     protoTCP,
	"LT_KCP_PORT":         protoUDP,
	"LT_VHOST_HTTP_PORT":  protoTCP,
	"LT_VHOST_HTTPS_PORT": protoTCP,
	"LT_FRPS_API_PORT":    protoTCP,
	"LT_USER_PORT":        protoTCP,
}

// validateVars 校验合并后的变量集合。
//
// res 里的 Warnings 是「能跑但不该这样配」的情况；返回 error 则是
// 「这样配根本跑不起来」——两者必须分开，否则管理员会被一堆
// 无害的提醒训练成「看到红色就往下点」。
func (s *service) validateVars(vars map[string]string, res *tlscfg.RenderResult) error {
	required := []string{
		"LT_GATEWAY_PORT", "LT_KCP_PORT", "LT_VHOST_HTTP_PORT", "LT_VHOST_HTTPS_PORT",
		"LT_FRPS_TOKEN", "LT_PORT_RANGE_START", "LT_PORT_RANGE_END", "LT_MAX_PORTS_PER_USER",
		"LT_FRPS_API_PORT", "LT_FRPS_API_USER", "LT_FRPS_API_PASSWORD", "LT_USER_PORT",
	}
	if err := requireVars(vars, required); err != nil {
		return err
	}

	for _, k := range sortedKeys(vars) {
		if strings.HasPrefix(strings.TrimSpace(vars[k]), "CHANGE_ME") {
			return fmt.Errorf("%s 仍是占位符，请改为真实值", k)
		}
	}

	panel := vars[tlscfg.VarPanelDomain]
	if panel == "" {
		return errors.New("面板域名为空：Caddy 需要一个站点地址（域名或 IP）")
	}
	if err := validDomain(panel); err != nil {
		return fmt.Errorf("面板域名不合法: %w", err)
	}

	tunnel := strings.TrimSpace(vars[tlscfg.VarTunnelDomain])
	if tunnel != "" {
		if strings.HasPrefix(tunnel, "*.") {
			return errors.New("隧道根域名要填裸域名（不含 *. 前缀）：泛域名前缀由模板自己加上")
		}
		if err := validDomain(tunnel); err != nil {
			return fmt.Errorf("隧道根域名不合法: %w", err)
		}
		if strings.EqualFold(tunnel, panel) {
			return errors.New("隧道根域名不能与面板域名相同：同一个域名既要 Caddy 提供控制台、又要按子域转发隧道，会更早耗尽证书配额且难以排查")
		}
		// 泛域名证书只能走 DNS Challenge，没有 dns 指令就签不出证书。
		if strings.TrimSpace(vars[tlscfg.VarDNSProvider]) == "" {
			return errors.New("已填写隧道根域名但未选择 DNS 服务商：泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证，只能用 DNS Challenge")
		}
	}

	switch strings.ToLower(strings.TrimSpace(vars[tlscfg.VarHTTPSMode])) {
	case "", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E:
	default:
		return fmt.Errorf("HTTPS 隧道模式只能是 %s 或 %s", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E)
	}

	// DNS Challenge 需要镜像里有对应插件。这一条是本功能最容易踩的坑：
	// 配置全对，但镜像是官方的 caddy:2-alpine，Caddy 会以
	// "unrecognized directive: dns" 拒绝启动**整份**配置。
	provider := strings.TrimSpace(vars[tlscfg.VarDNSProvider])
	if provider != "" && tunnel != "" {
		image := s.effectiveCaddyImage(vars)
		if isOfficialCaddyImage(image) {
			return fmt.Errorf("DNS 服务商已选 %s，但 Caddy 镜像是官方镜像 %s：官方镜像不含任何 dns 插件，Caddy 会以 unrecognized directive: dns 拒绝启动。"+
				"请按 deploy/caddy/Dockerfile 自建镜像（LT_CADDY_DNS_MODULES=%s）并把 LT_CADDY_IMAGE 指向它", provider, image, provider)
		}
		if mods := strings.Fields(vars["LT_CADDY_DNS_MODULES"]); len(mods) > 0 && !containsFold(mods, provider) {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"LT_CADDY_DNS_MODULES（%s）里没有 %s 插件，但镜像可能已另行构建；若 Caddy 启动失败请检查插件是否编入",
				strings.Join(mods, " "), provider))
		}
	}

	// 端到端 HTTPS：入口是 frps 的 vhostHTTPSPort，必须真的对公网放行。
	if strings.EqualFold(vars[tlscfg.VarHTTPSMode], tlscfg.HTTPSModeE2E) {
		if port, err := strconv.Atoi(vars["LT_VHOST_HTTPS_PORT"]); err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("端到端 HTTPS 需要合法的 LT_VHOST_HTTPS_PORT（当前 %q）", vars["LT_VHOST_HTTPS_PORT"])
		}
		res.Warnings = append(res.Warnings,
			"端到端 HTTPS 模式下，HTTPS 隧道走 frps 的独立端口而不是 443：请确认防火墙已放行该端口，"+
				"并且把 443 上的 HTTPS 请求指向该端口（443 由 Caddy 终止，用的是平台自己的泛域名证书）")
	}

	// 端口组：这几条规则面板侧的 config.Validate 一直在拦，helper 以前一条
	// 都不查——于是「端口池起点 443」「网关端口与 frps 管理端口相同」这类配置
	// 能一路写进 .env 并重建容器，直到运行期分配端口才以与配置无关的形式
	// 失败。helper 是最后一道闸，规则必须与面板一致。
	//
	// 顺序固定（不用 map 遍历）：错误信息要稳定，否则同一次错误每次重启
	// 报的是另一个端口，排查时对不上。
	portKeys := []string{
		"LT_GATEWAY_PORT", "LT_KCP_PORT", "LT_VHOST_HTTP_PORT",
		"LT_VHOST_HTTPS_PORT", "LT_FRPS_API_PORT", "LT_USER_PORT",
	}
	// 每个端口的传输层协议见 portProtocol：冲突判定必须带上协议，只按端口
	// 数字去重的话，LT_GATEWAY_PORT=7001 与 LT_KCP_PORT=7001 这一组完全合法
	// （也是 .env.example 明确写出的组合）会被判成冲突，管理员只能去改一个
	// 本来没问题的端口号。面板侧的端口池同样按 "tcp|"/"udp|" 两种键记录占用，
	// 说明协议本来就是判定的一部分。
	//
	// 注意这里判的是 **frps 基础设施端口**（网关 / KCP / vhost / API），不是
	// 隧道远程端口。隧道远程端口是**全局唯一**的（不分协议），由数据库唯一
	// 索引、端口池分配、端口锁与防火墙待办共同保证（见 model.Tunnel.RemotePort
	// 的注释）。两者刻意不同：内核允许基础设施端口按 TCP/UDP 各绑一份（KCP
	// 就靠这一点），而 frps 的 remote_port 是单一数字、防火墙待办也按数字
	// 收敛，没有协议维度可拆。若要把隧道模型改成 (protocol, port) 复合键，
	// 必须同时改那四处，不能只改这里的校验。
	seenPort := map[string]portOwner{
		portKey(protoTCP, 80):  {proto: protoTCP, name: "固定 HTTP 入口"},
		portKey(protoTCP, 443): {proto: protoTCP, name: "固定 HTTPS 入口"},
	}
	usedPorts := make([]int, 0, len(portKeys))
	for _, k := range portKeys {
		p, err := strconv.Atoi(strings.TrimSpace(vars[k]))
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("%s 不是合法端口（当前 %q）", k, vars[k])
		}
		proto := portProtocol[k]
		if prev, ok := seenPort[portKey(proto, p)]; ok {
			// 80/443 是 Caddy 的固定入口，分别允许由对应的 vhost
			// 变量显式使用；其它变量仍不得占用，也不能互相占用。
			// 固定入口走 TCP，所以这里只会与 TCP 变量相撞。
			allowedFixed := (p == 80 && k == "LT_VHOST_HTTP_PORT" && prev.name == "固定 HTTP 入口") ||
				(p == 443 && k == "LT_VHOST_HTTPS_PORT" && prev.name == "固定 HTTPS 入口")
			if !allowedFixed {
				return fmt.Errorf("%s(%s) 与 %s(%s) 使用了同一个端口 %d：同一台宿主机上它们必须互不相同（同一端口号只有分属 TCP 与 UDP 时可以共存）",
					k, proto, prev.name, prev.proto, p)
			}
		} else {
			seenPort[portKey(proto, p)] = portOwner{proto: proto, name: k}
		}
		usedPorts = append(usedPorts, p)
	}

	poolStart, errStart := strconv.Atoi(strings.TrimSpace(vars["LT_PORT_RANGE_START"]))
	poolEnd, errEnd := strconv.Atoi(strings.TrimSpace(vars["LT_PORT_RANGE_END"]))
	if errStart != nil || errEnd != nil || poolStart < 1024 || poolEnd <= poolStart || poolEnd > 65535 {
		return fmt.Errorf("端口池范围非法（%s-%s）：需满足 1024 <= 起始 < 结束 <= 65535",
			vars["LT_PORT_RANGE_START"], vars["LT_PORT_RANGE_END"])
	}
	maxPerUser, errMax := strconv.Atoi(strings.TrimSpace(vars["LT_MAX_PORTS_PER_USER"]))
	if errMax != nil || maxPerUser <= 0 {
		return fmt.Errorf("LT_MAX_PORTS_PER_USER 需为正整数（当前 %q）", vars["LT_MAX_PORTS_PER_USER"])
	}
	if capacity := poolEnd - poolStart + 1; maxPerUser > capacity {
		return fmt.Errorf("LT_MAX_PORTS_PER_USER（%d）超过端口池容量（%d）：单个用户就能占满整池",
			maxPerUser, capacity)
	}
	for i, k := range portKeys {
		// 池范围检查对所有端口变量一视同仁，不按协议区分：端口池里的端口
		// 会被同时当作 TCP 与 UDP 来用（面板侧按 "tcp|"/"udp|" 两种键记录
		// 占用），所以一个 UDP 端口落在池内同样会被运行期分配走。
		if usedPorts[i] >= poolStart && usedPorts[i] <= poolEnd {
			return fmt.Errorf("%s（%d）落在端口池 %d-%d 内：隧道分配会把它当成可用端口并尝试占用（TCP 与 UDP 都会被分配）",
				k, usedPorts[i], poolStart, poolEnd)
		}
	}

	res.RequiredPorts = []int{80, 443}
	if p := strings.TrimSpace(vars[tlscfg.VarHTTPSE2EPort]); p != "" {
		if port, err := strconv.Atoi(p); err == nil {
			res.RequiredPorts = append(res.RequiredPorts, port)
		}
	}
	return nil
}

// effectiveCaddyImage 决定用哪个镜像做校验。
func (s *service) effectiveCaddyImage(vars map[string]string) string {
	if v := strings.TrimSpace(s.caddyImage); v != "" {
		return v
	}
	if v := strings.TrimSpace(vars["LT_CADDY_IMAGE"]); v != "" {
		return v
	}
	return "caddy:2-alpine"
}

func isOfficialCaddyImage(image string) bool {
	image = strings.TrimSpace(image)
	return image == "" || image == "caddy" || strings.HasPrefix(image, "caddy:") || strings.HasPrefix(image, "docker.io/library/caddy")
}

// validateCaddy 用目标镜像校验渲染结果。
//
// 校验器与运行时镜像必须一致：两者的指令集不同（DNS 插件是编译期决定的），
// 换一个镜像校验就只剩下自我安慰的作用。
func (s *service) validateCaddy(ctx context.Context, text, image string, vars map[string]string) (string, error) {
	dir, err := s.tempDir(tempPrefixCaddy)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[lt-config] 清理 Caddy 校验目录失败（%s），请人工处理: %v", dir, err)
			s.registerDirtyScene()
			// 目录里有挂进容器的 DNS 凭据，必须让本次响应明确提示，
			// 而不是只留一行日志——日志会被滚掉，凭据不会自己消失。
			s.addWarn(fmt.Sprintf("Caddy 校验临时目录未能清理（%s）：%v；其中可能含 DNS 凭据，请人工删除", dir, err))
		}
	}()

	cfg := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()

	args := []string{
		"run", "--rm",
		"-v", dir + ":/w:ro",
		"-w", "/w",
	}
	// 把凭据传进校验容器：{env.LT_CADDY_DNS_CREDENTIAL} 取不到值时，
	// 部分服务商插件会在 provision 阶段直接报「没有凭据」，
	// 那样就成了一次与配置无关的误报。
	//
	// 但**不能用 `-e KEY=value`**：那种写法的值会出现在 docker 进程的命令行里
	// （/proc/<pid>/cmdline），宿主机上任何本地用户都能在容器启动的那一瞬读到。
	// 这是 DNS API 凭据，拿到就能改这个域名的解析记录。改用 env 文件：docker
	// 从文件读值，命令行上只有文件路径；文件按 0600 建在 0700 的临时目录里，
	// 校验结束随目录一起删除。
	if cred := vars[tlscfg.VarDNSCredential]; cred != "" {
		envPath := filepath.Join(dir, "caddy.env")
		if err := os.WriteFile(envPath, []byte(tlscfg.VarDNSCredential+"="+cred+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("写入校验用 env 文件失败: %w", err)
		}
		args = append(args, "--env-file", envPath)
	}
	args = append(args, image, "caddy", "validate", "--config", "/w/Caddyfile", "--adapter", "caddyfile")

	out, err := runDocker(ctx, args...)
	if err != nil {
		if isHostDockerError(err) {
			return out, hostError(fmt.Errorf("校验 Caddy 配置时 Docker 不可用：%s", strings.TrimSpace(out)))
		}
		return out, fmt.Errorf("Caddy 配置校验未通过：%s", strings.TrimSpace(out))
	}
	return "Caddy：" + strings.TrimSpace(out), nil
}

// validateContainers 用**将要上线的那个镜像**实际跑一遍校验。
//
// 两层分工：validateVars 看变量本身（能指出是哪个字段的问题），这里看这份
// 渲染结果在那个镜像里能不能起来。两者都不通过就不该写盘。
func (s *service) validateContainers(ctx context.Context, caddyText, caddyImage, frpsText string, vars map[string]string) (string, error) {
	if s.validateFn != nil {
		return s.validateFn(caddyText, caddyImage, frpsText, vars)
	}
	out, err := s.validateCaddy(ctx, caddyText, caddyImage, vars)
	if err != nil {
		return "", err
	}
	if !s.validateFrps {
		return out, nil
	}
	frpsOut, err := s.validateFrpsConfig(ctx, frpsText)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out + "\n" + frpsOut), nil
}

// validateFrpsConfig 用 frps 自带的 verify 子命令校验。
func (s *service) validateFrpsConfig(ctx context.Context, text string) (string, error) {
	dir, err := s.tempDir(tempPrefixFrps)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[lt-config] 清理 frps 校验目录失败（%s），请人工处理: %v", dir, err)
			s.registerDirtyScene()
			s.addWarn(fmt.Sprintf("frps 校验临时目录未能清理（%s）：%v；请人工删除", dir, err))
		}
	}()

	cfg := filepath.Join(dir, "frps.toml")
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()

	args := []string{
		"run", "--rm",
		"-v", dir + ":/w:ro",
		"-w", "/w",
		s.frpsImage,
		"verify", "-c", "/w/frps.toml",
	}
	out, err := runDocker(ctx, args...)
	if err != nil {
		if isHostDockerError(err) {
			return out, hostError(fmt.Errorf("校验 frps 配置时 Docker 不可用：%s", strings.TrimSpace(out)))
		}
		return out, fmt.Errorf("frps 配置校验未通过：%s（若所用镜像不带 verify 子命令，可用 LT_CFG_VALIDATE_FRPS=false 关闭该校验）",
			strings.TrimSpace(out))
	}
	return "frps：" + strings.TrimSpace(out), nil
}

// tempDir 在**部署目录**下创建临时目录。
//
// 为什么不放在 /tmp：校验是把临时目录挂进容器交给 docker 守护进程去读的，
// 而守护进程在宿主机的挂载命名空间里解析这个路径。systemd 单元默认开着
// PrivateTmp，此时 /tmp 是本服务私有的，守护进程根本看不到里面的文件
// ——报错会是 "no such file or directory"，与真正的原因毫无关系。
func (s *service) tempDir(prefix string) (string, error) {
	return os.MkdirTemp(s.paths.deployDir, "."+prefix)
}

// 校验临时目录的名字前缀（MkdirTemp 会在前面再加一个点）。
//
// 集中定义是为了让启动清理能认出来：这些目录里有挂进容器的凭据 env 文件，
// 异常退出后不删就等于把 DNS API 凭据长期留在部署目录里。
const (
	tempPrefixCaddy = "lt-config-caddy-"
	tempPrefixFrps  = "lt-config-frps-"
)

// validateTempDirPrefixes 是全部校验临时目录前缀。
var validateTempDirPrefixes = []string{tempPrefixCaddy, tempPrefixFrps}

// isValidateTempDir 判断目录名是否为本服务的校验临时目录。
func isValidateTempDir(name string) bool {
	for _, p := range validateTempDirPrefixes {
		if strings.HasPrefix(name, "."+p) {
			return true
		}
	}
	return false
}

// validDomain 校验裸域名。
//
// 只接受字母数字与 '-' 组成的标签，并且不含空白与斜杠：
// 值会被拼进配置文件，任何异常字符都可能让配置变得不可预期。
func validDomain(d string) error {
	d = strings.TrimSpace(d)
	if d == "" {
		return errors.New("不能为空")
	}
	if strings.ContainsAny(d, " \t\r\n/\\*") {
		return fmt.Errorf("%q 含有非法字符（只填裸域名，不带 scheme、路径或 *）", d)
	}
	if len(d) > 253 {
		return errors.New("过长")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q 不是完整域名（至少需要两段，如 panel.example.com）", d)
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%q 存在空的域名段", d)
		}
		for _, r := range l {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("%q 含有非法字符 %q", d, string(r))
		}
	}
	return nil
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

// requireVars 从 .env 解析结果里取出必填项。
//
// 「缺必填项」与「值不合法」分开报：前者是部署目录的 .env 不完整（多半是没填
// 或键名写错），后者是填了但内容有问题。两者的修法不同，合并成一句会让管理员
// 在配置页与 .env 之间来回猜。
func requireVars(vars map[string]string, keys []string) error {
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(vars[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("部署目录的 .env 缺少必填项: %s", strings.Join(missing, ", "))
	}
	return nil
}
