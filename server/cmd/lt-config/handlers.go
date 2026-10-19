package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func redactSecret(secret, text string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) < 4 {
		return text
	}
	return strings.ReplaceAll(text, secret, "***")
}

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
		envErr = err
	}
	docker := s.fillDockerHealth(&h)
	if !docker.Found {
		h.Available = false
		h.Reason = docker.Reason
	}
	if h.Available {
		for _, f := range []string{s.paths.caddyTpl, s.paths.frpsTpl, s.paths.envFile, s.paths.composeFile} {
			state, err := statRegularFileState(f)
			switch state {
			case fileMissing:
				h.Available = false
				h.Reason = fmt.Sprintf("缺少文件 %s", f)
			case fileUnknown:
				h.Available = false
				h.Reason = fmt.Sprintf("无法读取 %s（%v）：请检查部署目录的权限与挂载", f, err)
			case fileNotRegular:
				h.Available = false
				h.Reason = fmt.Sprintf("%s 不是普通文件（可能是目录）：请检查部署目录", f)
			}
			if !h.Available {
				break
			}
		}
	}
	if envErr != nil {
		h.Available = false
		h.Reason = fmt.Sprintf("无法读取 %s（%v）：请检查部署目录的权限与挂载", s.paths.envFile, envErr)
	}
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
	if req.Vars == nil {
		req.Vars = map[string]string{}
	}

	res, err := s.renderAndApply(r.Context(), req)
	if err != nil {
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
		if errors.Is(err, errApplyBusy) {
			failJSON(w, http.StatusConflict, err)
			return
		}
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

func (s *service) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 POST"))
		return
	}
	if !s.allowApply {
		failJSON(w, http.StatusForbidden, errors.New("本服务以只渲染模式启动（LT_CFG_APPLY=false），不会重建容器"))
		return
	}
	if !s.applyMu.TryLock() {
		failJSON(w, http.StatusConflict, errApplyBusy)
		return
	}
	defer s.applyMu.Unlock()

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
