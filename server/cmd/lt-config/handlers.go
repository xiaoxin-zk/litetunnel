package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

// handleHealth 报告自身可用性与部署目录的端口。
//
// 面板打开设置页就会调它，因此这里的检查都很廉价：文件在不在、docker 命令
// 在不在。唯一会起进程的是 docker 可用性探测，它按 TTL 缓存并单飞（见
// dockerStatus，实现在 dockerprobe.go），否则高频轮询会变成宿主机上的进程风暴。
func (s *service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 GET"))
		return
	}

	h := tlscfg.Health{DeployDir: s.paths.deployDir, Available: true, BlockedDirs: s.blockedDirsSnapshot()}
	var envErr error
	if _, vars, err := readEnvFile(s.paths.envFile); err == nil {
		h.Ports = tlscfg.Ports{
			Gateway:    atoiOr(vars["LT_GATEWAY_PORT"], 0),
			KCP:        atoiOr(vars["LT_KCP_PORT"], 0),
			VhostHTTP:  atoiOr(vars["LT_VHOST_HTTP_PORT"], 0),
			VhostHTTPS: atoiOr(vars["LT_VHOST_HTTPS_PORT"], 0),
		}
	} else {
		// .env 读不出来时不能报告可用：端口显示为空、而面板照样允许点保存，
		// 真正的原因（权限/挂载）会被埋在应用失败的错误里。
		envErr = err
	}
	// docker 分两层报告：Docker 只说明命令在 PATH 里，DockerReady 才说明
	// 宿主机现在真的能起容器。二者分开是为了让面板能给出准确的下一步——
	// 命令不在要装 docker，daemon 不通要去看服务，两者的处理方式完全不同。
	// 探测与组装都在 dockerprobe.go，这里只决定它如何影响 Available。
	docker := s.fillDockerHealth(&h)
	if !docker.Found {
		h.Available = false
		h.Reason = docker.Reason
	}
	if h.Available {
		for _, f := range []string{s.paths.caddyTpl, s.paths.frpsTpl, s.paths.envFile, s.paths.composeFile} {
			// 这里同样是三态（见 statcheck.go）：Stat 失败不等于「文件不存在」。
			// 判不出来（权限不足、目录挂载丢了、I/O 出错）时报「缺少文件」会把
			// 管理员引去补一个其实还在的文件，所以两种情况分开写。
			state, err := statFileState(f)
			switch state {
			case fileMissing:
				h.Available = false
				h.Reason = fmt.Sprintf("缺少文件 %s", f)
			case fileUnknown:
				h.Available = false
				h.Reason = fmt.Sprintf("无法读取 %s（%v）：请检查部署目录的权限与挂载", f, err)
			}
			if !h.Available {
				break
			}
		}
	}
	// .env 读不出来时覆盖前两步的结论：缺 docker 可以装，缺模板可以补，
	// 而「配置源本身读不到」会让后续每一次保存都在同一个地方失败。
	if envErr != nil {
		h.Available = false
		h.Reason = fmt.Sprintf("无法读取 %s（%v）：请检查部署目录的权限与挂载", s.paths.envFile, envErr)
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
			if partial.servicesErr != nil {
				res.ServicesError = redactSecret(req.Vars[tlscfg.VarDNSCredential], partial.servicesErr.Error())
			}
			res.Applied = false
			res.Message = redactSecret(req.Vars[tlscfg.VarDNSCredential], partial.msg)
			writeJSON(w, http.StatusOK, res)
			return
		}
		// 另一个应用还在跑：409，让前端提示「等它结束」。绝不能排队——
		// 排队会让第二个事务在第一个超时之后才开始改盘。
		if errors.Is(err, errApplyBusy) {
			failJSON(w, http.StatusConflict, err)
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
	//
	// 同样用 TryLock：重建容器的耗时不可控，排队只会把请求堆到超时之后。
	if !s.applyMu.TryLock() {
		failJSON(w, http.StatusConflict, errApplyBusy)
		return
	}
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
