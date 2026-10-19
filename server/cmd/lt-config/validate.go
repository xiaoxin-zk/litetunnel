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

const (
	protoTCP = "TCP"
	protoUDP = "UDP"
)

func portKey(proto string, port int) string {
	return proto + ":" + strconv.Itoa(port)
}

type portOwner struct {
	proto string
	name  string
}

var portProtocol = map[string]string{
	"LT_GATEWAY_PORT":     protoTCP,
	"LT_KCP_PORT":         protoUDP,
	"LT_VHOST_HTTP_PORT":  protoTCP,
	"LT_VHOST_HTTPS_PORT": protoTCP,
	"LT_FRPS_API_PORT":    protoTCP,
	"LT_USER_PORT":        protoTCP,
}

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
	if err := validPanelDomain(panel); err != nil {
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
		if strings.TrimSpace(vars[tlscfg.VarDNSProvider]) == "" {
			return errors.New("已填写隧道根域名但未选择 DNS 服务商：泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证，只能用 DNS Challenge")
		}
	}

	switch strings.ToLower(strings.TrimSpace(vars[tlscfg.VarHTTPSMode])) {
	case "", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E:
	default:
		return fmt.Errorf("HTTPS 隧道模式只能是 %s 或 %s", tlscfg.HTTPSModeEdge, tlscfg.HTTPSModeE2E)
	}

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

	if strings.EqualFold(vars[tlscfg.VarHTTPSMode], tlscfg.HTTPSModeE2E) {
		if port, err := strconv.Atoi(vars["LT_VHOST_HTTPS_PORT"]); err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("端到端 HTTPS 需要合法的 LT_VHOST_HTTPS_PORT（当前 %q）", vars["LT_VHOST_HTTPS_PORT"])
		}
		res.Warnings = append(res.Warnings,
			"端到端 HTTPS 模式下，HTTPS 隧道走 frps 的独立端口而不是 443：请确认防火墙已放行该端口，"+
				"并且把 443 上的 HTTPS 请求指向该端口（443 由 Caddy 终止，用的是平台自己的泛域名证书）")
	}

	portKeys := []string{
		"LT_GATEWAY_PORT", "LT_KCP_PORT", "LT_VHOST_HTTP_PORT",
		"LT_VHOST_HTTPS_PORT", "LT_FRPS_API_PORT", "LT_USER_PORT",
	}
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

func (s *service) validateCaddy(ctx context.Context, text, image string, vars map[string]string) (string, error) {
	dir, err := s.tempDir(tempPrefixCaddy)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[lt-config] 清理 Caddy 校验目录失败（%s），请人工处理: %v", dir, err)
			s.registerDirtyScene()
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

func (s *service) tempDir(prefix string) (string, error) {
	return os.MkdirTemp(s.paths.deployDir, "."+prefix)
}

const (
	tempPrefixCaddy = "lt-config-caddy-"
	tempPrefixFrps  = "lt-config-frps-"
)

var validateTempDirPrefixes = []string{tempPrefixCaddy, tempPrefixFrps}

func isValidateTempDir(name string) bool {
	for _, p := range validateTempDirPrefixes {
		if strings.HasPrefix(name, "."+p) {
			return true
		}
	}
	return false
}

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

func validPanelDomain(d string) error {
	d = strings.TrimSpace(d)
	host, port := d, ""
	if i := strings.IndexByte(d, ':'); i >= 0 {
		if strings.Count(d, ":") > 1 {
			return fmt.Errorf("%q 含有非法字符 %q（IPv6 地址暂不支持，请改用域名或 IPv4）", d, ":")
		}
		host, port = d[:i], d[i+1:]
		if port == "" {
			return fmt.Errorf("%q 的端口为空", d)
		}
	}
	if err := validDomain(host); err != nil {
		return err
	}
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q 的端口 %q 不合法（需 1-65535 的整数）", d, port)
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
