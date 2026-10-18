package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
// 面板打开设置页就会调它，因此这里只做廉价检查（文件在不在、docker 有没有），
// 不碰网络也不起容器。
func (s *service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 GET"))
		return
	}

	h := tlscfg.Health{DeployDir: s.paths.deployDir, Available: true}
	if _, vars, err := readEnvFile(s.paths.envFile); err == nil {
		h.Ports = tlscfg.Ports{
			Gateway:    atoiOr(vars["LT_GATEWAY_PORT"], 0),
			KCP:        atoiOr(vars["LT_KCP_PORT"], 0),
			VhostHTTP:  atoiOr(vars["LT_VHOST_HTTP_PORT"], 0),
			VhostHTTPS: atoiOr(vars["LT_VHOST_HTTPS_PORT"], 0),
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		h.Docker = false
		h.Available = false
		h.Reason = "未找到 docker 命令：校验与重建容器都依赖它"
	} else {
		h.Docker = true
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

	res, err := s.renderAndApply(r.Context(), req)
	if err != nil {
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
