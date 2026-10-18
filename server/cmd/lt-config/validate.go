package main

import (
	"context"
	"errors"
	"fmt"
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
	dir, err := s.tempDir("lt-config-caddy-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()

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
	dir, err := s.tempDir("lt-config-frps-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()

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
