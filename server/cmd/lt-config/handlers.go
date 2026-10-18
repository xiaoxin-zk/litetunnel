package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件只做 HTTP 层的事：解析请求、决定状态码、把结果回给面板。
// 真正的渲染、校验、写盘与重建容器分别在 apply.go / validate.go / compose.go。
//
// 分开的理由不是「文件太长」本身，而是这三件事的失败方式完全不同：
// 请求错了是 4xx、配置不对是 422（可原地改配置）、宿主机动不了手是 502
//（要去查服务）。混在一个文件里时，很容易顺手把所有失败都塞进一个出口。

// redactSecret 把密钥从任何要回传给面板的文本里抹掉。
//
// 为什么需要它：DNS 服务商插件在凭据无效时，打印的错误里往往带着凭据本身。
// 这段文本会经面板显示在浏览器里，也就进了截图、工单与聊天记录。
func redactSecret(secret, text string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) < 4 {
		return text
	}
	return strings.ReplaceAll(text, secret, "***")
}

// dockerProbeTimeout 是一次 docker 可用性探测的时间上限。
//
// 必须压得很短：/health 会被面板与部署脚本高频轮询，而 daemon 不通时
// docker CLI 自己可能要等十几秒（DOCKER_HOST 指向不响应的 socket、宿主
// 磁盘 hang）。没有上限的话，一次卡住就把探测锁与请求一起拖住，健康检查
// 从「报告状态」变成「又一个超时」。
const dockerProbeTimeout = 2 * time.Second

// dockerProbeTTL 是探测结果的缓存时长。
//
// 每次请求都起一个 docker 进程是不能接受的：每次探测都要连一次 daemon
// （unix socket / Windows 命名管道），部署脚本轮询时那是稳定的进程风暴，
// 而 docker 探测本身还会占住 daemon 的一次连接。
//
// TTL 取 10 秒级而不是更长：管理员刚把 daemon 拉起来、或刚把本服务加进
// docker 组，界面应当在十几秒内反映出来；再长就会让「修好了却还显示不可用」
// 变成一次新的排查。
const dockerProbeTTL = 12 * time.Second

// dockerProbeResult 是一次 docker 可用性探测的结论。
type dockerProbeResult struct {
	// Found 表示 PATH 里有 docker 命令。
	Found bool
	// Ready 表示宿主机侧真的能用：daemon 可达、当前身份有权限。
	Ready bool
	// Reason 是失败时的可读中文原因。
	Reason string
}

// dockerProbeCache 缓存探测结果，并保证同一时刻只有一次探测在跑。
//
// 用互斥锁而不是放开并发：并发请求同时过期时各自起一个 docker 进程毫无
// 意义，还会在 daemon 卡顿时叠加等待。持有锁期间其余请求直接排队，拿到
// 的是这一次的结果。
type dockerProbeCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	valid     bool
	result    dockerProbeResult
}

// dockerStatus 返回 docker 可用性结论，必要时做一次带缓存的探测。
func (s *service) dockerStatus() dockerProbeResult {
	s.dockerProbe.mu.Lock()
	defer s.dockerProbe.mu.Unlock()
	now := time.Now()
	if s.dockerProbe.valid && now.Sub(s.dockerProbe.checkedAt) < dockerProbeTTL {
		return s.dockerProbe.result
	}
	res := s.probeDocker()
	s.dockerProbe.checkedAt = now
	s.dockerProbe.valid = true
	s.dockerProbe.result = res
	return res
}

// probeDocker 做一次真实探测（不受缓存约束），测试里可替换。
func (s *service) probeDocker() dockerProbeResult {
	if s.dockerProbeFn != nil {
		return s.dockerProbeFn()
	}
	return probeDockerHost()
}

// probeDockerHost 区分「命令在」与「宿主机可用」。
//
// 只做 exec.LookPath 是过去的问题所在：把 docker 装在机器上、却没启动
// daemon（或本服务没有 socket 权限）时，LookPath 一样成功，于是面板显示
// 一切正常，直到管理员点「保存」——那时文件已经写盘、容器重建到一半失败，
// 磁盘与容器分处两个版本。
//
// 用 docker info 而不是更轻的 --version：后者只打印客户端版本，完全不连
// daemon，仍然证明不了宿主机可用。
func probeDockerHost() dockerProbeResult {
	if _, err := exec.LookPath("docker"); err != nil {
		return dockerProbeResult{Reason: "未找到 docker 命令：校验与重建容器都依赖它"}
	}
	// 探测用自己的超时根上下文，不继承请求可能已被取消的 ctx：
	// 否则一次取消会把「探测失败」写进缓存，接下来十几秒的健康检查都在
	// 报一个已经不成立的原因。
	ctx, cancel := context.WithTimeout(context.Background(), dockerProbeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		return dockerProbeResult{Found: true, Ready: true}
	}
	if ctx.Err() != nil {
		return dockerProbeResult{Found: true, Reason: fmt.Sprintf(
			"docker 命令存在，但 %s 内没有响应（daemon 可能卡住或未启动）：%s",
			dockerProbeTimeout, truncateRunes(text, 200))}
	}
	if text == "" {
		text = err.Error()
	}
	return dockerProbeResult{Found: true, Reason: "docker 命令存在，但宿主机不可用（daemon 未启动、无 socket 权限或 compose 插件缺失）：" +
		truncateRunes(text, 200)}
}

// truncateRunes 截断过长的命令输出，避免整段 docker 报错灌进健康检查响应。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// handleHealth 报告自身可用性与部署目录的端口。
//
// 面板打开设置页就会调它，因此这里的检查都很廉价：文件在不在、docker 命令
// 在不在。唯一会起进程的是 docker 可用性探测，它按 TTL 缓存并单飞（见
// dockerStatus），否则高频轮询会变成宿主机上的进程风暴。
func (s *service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 GET"))
		return
	}

	h := tlscfg.Health{DeployDir: s.paths.deployDir, Available: true, BlockedDirs: s.blockedDirsSnapshot()}
	if _, vars, err := readEnvFile(s.paths.envFile); err == nil {
		h.Ports = tlscfg.Ports{
			Gateway:    atoiOr(vars["LT_GATEWAY_PORT"], 0),
			KCP:        atoiOr(vars["LT_KCP_PORT"], 0),
			VhostHTTP:  atoiOr(vars["LT_VHOST_HTTP_PORT"], 0),
			VhostHTTPS: atoiOr(vars["LT_VHOST_HTTPS_PORT"], 0),
		}
	}
	// docker 分两层报告：Docker 只说明命令在 PATH 里，DockerReady 才说明
	// 宿主机现在真的能起容器。二者分开是为了让面板能给出准确的下一步——
	// 命令不在要装 docker，daemon 不通要去看服务，两者的处理方式完全不同。
	docker := s.dockerStatus()
	h.Docker = docker.Found
	h.DockerReady = docker.Ready
	if !docker.Ready {
		h.DockerErr = docker.Reason
	}
	if !docker.Found {
		h.Available = false
		h.Reason = docker.Reason
	}
	if h.Available {
		for _, f := range []string{s.paths.caddyTpl, s.paths.frpsTpl, s.paths.envFile, s.paths.composeFile} {
			if _, err := os.Stat(f); err != nil {
				h.Available = false
				h.Reason = fmt.Sprintf("缺少文件 %s", f)
				break
			}
		}
	}
	// 现场未收敛放在最后判断：它是「必须人工介入」的状态，比缺 docker、
	// 缺文件更该先处理，Reason 也以它为准——否则界面显示「缺少某个文件」，
	// 管理员去补文件，却发现保存仍然失败。
	if dir := s.dirtyDir(); dir != "" {
		h.Available = false
		h.Reason = fmt.Sprintf("部署目录 %s 存在未能自动收敛的配置现场，写盘已被拒绝，需人工确认后清理", dir)
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *service) handleRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 POST"))
		return
	}
	var req tlscfg.RenderRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		failJSON(w, http.StatusBadRequest, errors.New("请求体格式不正确"))
		return
	}
	// vars 缺省（请求体省略或显式传 null）统一归一成空 map：渲染流程后续会对
	// 变量做读取与派生写入，归一成非 nil 可避免任何一处误写到 nil map 引发 panic。
	if req.Vars == nil {
		req.Vars = map[string]string{}
	}

	res, err := s.renderAndApply(r.Context(), req)
	if err != nil {
		// 部分应用必须单独返回：既不是成功，也不是「什么都没发生」。
		// 只回一句「重建失败」的话，管理员无从判断磁盘与新配置哪个生效了。
		var partial *partialApplyError
		if errors.As(err, &partial) {
			res.Partial = true
			res.Services = partial.services
			res.Applied = false
			res.Message = redactSecret(req.Vars[tlscfg.VarDNSCredential], partial.msg)
			writeJSON(w, http.StatusOK, res)
			return
		}
		// 按错误类别区分状态码：配置错 422（原地改配置）、宿主机错 502（去查
		// docker）、读盘/写盘错 500（看本服务日志）。返回前先脱敏：校验输出里
		// 可能带回服务商插件打印的凭据片段。
		code := http.StatusUnprocessableEntity
		switch classifyError(err) {
		case kindHost:
			code = http.StatusBadGateway
		case kindInternal:
			code = http.StatusInternalServerError
		}
		failJSON(w, code, errors.New(redactSecret(req.Vars[tlscfg.VarDNSCredential], err.Error())))
		return
	}
	res.Validate = redactSecret(req.Vars[tlscfg.VarDNSCredential], res.Validate)
	for i := range res.Warnings {
		res.Warnings[i] = redactSecret(req.Vars[tlscfg.VarDNSCredential], res.Warnings[i])
	}
	writeJSON(w, http.StatusOK, res)
}

// handleApply 只用当前磁盘上的文件重建容器。
//
// 存在这个入口是因为「渲染与校验都过了、重启却失败」很常见
// （docker 忙、镜像正在被别的操作使用）。管理员修好后点一下重试即可。
func (s *service) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 POST"))
		return
	}
	if !s.allowApply {
		failJSON(w, http.StatusForbidden, errors.New("本服务以只渲染模式启动（LT_CFG_APPLY=false），不会重建容器"))
		return
	}
	// 与 /render 共用同一把锁：否则容器可能重建在「文件替换到一半」的瞬间，
	// 起出来的进程读到的就是一份新旧混合的配置。
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	// 现场未收敛时同样拒绝：磁盘可能是新旧混合，按它重建容器等于把混合
	// 状态跑起来，还会让「哪一版在跑」更难判断。409 而不是 500——这不是
	// 服务出错，是需要人来做决定。
	if dir := s.dirtyDir(); dir != "" {
		failJSON(w, http.StatusConflict, s.dirtySceneError(dir))
		return
	}

	out, err := s.composeUp(r.Context())
	if err != nil {
		failJSON(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, tlscfg.RenderResult{
		Applied:  true,
		Message:  "已重建 caddy 与 frps 容器",
		Validate: out,
	})
}
