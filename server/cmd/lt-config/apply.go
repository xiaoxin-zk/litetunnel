package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

func (s *service) renderAndApply(ctx context.Context, req tlscfg.RenderRequest) (tlscfg.RenderResult, error) {
	var res tlscfg.RenderResult

	if !s.applyMu.TryLock() {
		return res, errApplyBusy
	}
	defer s.applyMu.Unlock()

	_ = s.takeWarns()

	if dir := s.dirtyDir(); dir != "" {
		return res, s.dirtySceneError(dir)
	}

	env, vars, err := readEnvFile(s.paths.envFile)
	if err != nil {
		return res, internalError(fmt.Errorf("读取 %s 失败: %w", s.paths.envFile, err))
	}

	for _, k := range sortedKeys(req.Vars) {
		if !tlscfg.IsOverridable(k) {
			return res, fmt.Errorf("不允许覆盖变量 %s", k)
		}
		v := strings.TrimSpace(req.Vars[k])
		if tlscfg.HasControlChars(v) {
			return res, fmt.Errorf("变量 %s 的值含有换行或其他控制字符：写进 .env 会变成额外的配置行", k)
		}
		vars[k] = v
	}
	log.Printf("[lt-config] 面板下发的变量: %v", tlscfg.Redact(req.Vars))

	deriveVars(vars)

	caddyImage := s.effectiveCaddyImage(vars)
	if composeImage := tlscfg.ComposeCaddyImage(vars); caddyImage != composeImage {
		return res, fmt.Errorf(
			"校验用的 Caddy 镜像（%s）与 Compose 实际会使用的镜像（%s）不一致："+
				"请让 LT_CFG_CADDY_IMAGE 与 .env 的 LT_CADDY_IMAGE 相同，或取消前者",
			caddyImage, composeImage)
	}

	if err := s.validateVars(vars, &res); err != nil {
		return res, err
	}

	caddyTpl, err := readConfigInput(s.paths.caddyTpl)
	if err != nil {
		return res, internalError(fmt.Errorf("读取 Caddyfile 模板失败: %w", err))
	}
	frpsTpl, err := readConfigInput(s.paths.frpsTpl)
	if err != nil {
		return res, internalError(fmt.Errorf("读取 frps.toml 模板失败: %w", err))
	}
	caddyText, err := tlscfg.Render(string(caddyTpl), vars)
	if err != nil {
		return res, fmt.Errorf("渲染 Caddyfile 失败: %w", err)
	}
	frpsText, err := tlscfg.Render(string(frpsTpl), vars)
	if err != nil {
		return res, fmt.Errorf("渲染 frps.toml 失败: %w", err)
	}

	validateOut, err := s.validateContainers(ctx, caddyText, caddyImage, frpsText, vars)
	if err != nil {
		return res, err
	}
	res.Validate = validateOut
	res.Warnings = append(res.Warnings, s.takeWarns()...)

	writes := []pendingWrite{
		{name: "Caddyfile", path: s.paths.caddyOut, content: caddyText, mode: modeConfig},
		{name: "frps.toml", path: s.paths.frpsOut, content: frpsText, mode: modeSecret},
	}

	if req.WriteEnv {
		for _, k := range sortedKeys(req.Vars) {
			changed, err := env.set(k, vars[k])
			if err != nil {
				return res, err
			}
			if changed {
				res.EnvUpdated = append(res.EnvUpdated, k)
			}
		}
		writes = append(writes, pendingWrite{
			name: ".env", path: s.paths.envFile, content: env.content(), mode: modeSecret,
		})
	}

	if req.Apply && !req.WriteEnv {
		return res, errors.New("Apply=true 必须同时 WriteEnv=true：否则模板文件与容器读取的 .env 会不一致")
	}
	if !req.Apply {
		res.Changed = pendingChanges(writes)
		res.Message = "配置已生成并通过校验（未写入、未应用）"
		return res, nil
	}
	if !s.allowApply {
		return res, errors.New("本服务以只渲染模式启动（LT_CFG_APPLY=false），配置未写入、也未重建容器")
	}

	if err := ctx.Err(); err != nil {
		return res, err
	}

	batch, err := prepareWrites(writes)
	if err != nil {
		return res, internalError(err)
	}
	res.Warnings = append(res.Warnings, batch.warn...)
	if err := batch.commit(); err != nil {
		return res, s.commitFailure(err)
	}
	res.Changed = sortedChanged(batch.changed)

	if len(batch.changed) == 0 {
		res.Applied = false
		res.Message = "配置内容无变化，未重建容器"
		return res, nil
	}

	if err := ctx.Err(); err != nil {
		rbErr := batch.revert()
		if rbErr != nil && !errors.Is(rbErr, errBatchCleanupPending) {
			return res, fmt.Errorf("请求在写盘后中断，且回滚磁盘失败（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", err, rbErr)
		}
		if rbErr != nil {
			s.registerDirtyScene()
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("配置已回滚为旧配置，但批次记录未清理：重启时恢复逻辑会再按它处理一遍整批文件，需人工确认后清理\n%v", rbErr))
		}
		return res, err
	}

	out, upErr := s.composeUp(ctx)
	if upErr != nil {
		return res, s.recoverFromFailedApply(ctx, batch, upErr, out)
	}

	if err := batch.finalize(); err != nil {
		if errors.Is(err, errBatchRecoveryAtRisk) {
			s.registerDirtyScene()
			statesCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			states, stateErr := s.serviceStates(statesCtx)
			cancel()
			if stateErr != nil {
				states = nil
			}
			return res, &partialApplyError{
				msg:         fmt.Sprintf("配置与容器均已生效，但批次现场无法落定：重启可能把磁盘回滚到旧配置，需人工处理\n%v", err),
				services:    states,
				servicesErr: stateErr,
				cause:       err,
			}
		}
		res.Warnings = append(res.Warnings, err.Error())
	}
	res.Applied = true
	res.Validate = strings.TrimSpace(res.Validate + "\n" + out)
	res.Message = "配置已应用，caddy 与 frps 已重建"
	return res, nil
}

var errApplyBusy = errors.New("另一个配置应用正在进行，请等待它结束后重试")

type partialApplyError struct {
	msg         string
	services    []tlscfg.ServiceState
	servicesErr error
	cause       error
}

func (e *partialApplyError) Error() string { return e.msg }

func (e *partialApplyError) Unwrap() error { return e.cause }

const rollbackTimeout = 3 * time.Minute

func (s *service) recoverFromFailedApply(reqCtx context.Context, batch *writeBatch, upErr error, upOut string) error {
	detail := strings.TrimSpace(upOut)
	if detail != "" {
		detail = "\n" + detail
	}
	if err := reqCtx.Err(); err != nil {
		detail += fmt.Sprintf("\n（原请求已中断：%v；回滚使用独立预算继续执行）", err)
	}

	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()

	rbErr := batch.revert()
	cleanupPending := errors.Is(rbErr, errBatchCleanupPending)
	if rbErr != nil && !cleanupPending {
		s.registerDirtyScene()
		states, stateErr := s.serviceStates(rollbackCtx)
		return &partialApplyError{
			msg: fmt.Sprintf("容器重建失败，磁盘回滚也失败：磁盘与新容器可能都是新配置，需人工处理"+
				"\n重建错误: %v\n回滚错误: %v%s", upErr, rbErr, detail),
			services:    states,
			servicesErr: stateErr,
			cause:       rbErr,
		}
	}
	note := ""
	if cleanupPending {
		s.registerDirtyScene()
		note = "；但批次记录未清理，重启后恢复逻辑会按它再回滚一遍整批文件（可能覆盖此后的手工修改），需人工确认后清理"
	}

	if _, reErr := s.composeUp(rollbackCtx); reErr == nil {
		return fmt.Errorf("%w（磁盘与容器均已回滚到旧配置%s，可修改后重试）%s", upErr, note, detail)
	} else {
		s.registerDirtyScene()
		states, stateErr := s.serviceStates(rollbackCtx)
		return &partialApplyError{
			msg: fmt.Sprintf("新配置重建失败，磁盘已回滚为旧配置，但按旧配置重建也失败：容器当前版本未知"+
				"\n新配置重建错误: %v\n回滚重建错误: %v%s", upErr, reErr, detail),
			services:    states,
			servicesErr: stateErr,
			cause:       reErr,
		}
	}
}

func deriveVars(vars map[string]string) {
	publicURL := strings.ToLower(strings.TrimSpace(vars[tlscfg.VarUserPublicURL]))
	scheme := "https"
	if strings.HasPrefix(publicURL, "http://") {
		scheme = "http"
	}
	vars[tlscfg.VarPanelScheme] = scheme
	if scheme == "https" {
		vars[tlscfg.VarHSTSOn] = "1"
	} else {
		vars[tlscfg.VarHSTSOn] = ""
	}
	if v := stripScheme(vars[tlscfg.VarUserPublicURL]); v != "" {
		vars[tlscfg.VarPanelDomain] = v
	}
	if vars[tlscfg.VarACMEEmail] == "" && vars[tlscfg.VarPanelDomain] != "" {
		vars[tlscfg.VarACMEEmail] = "admin@" + vars[tlscfg.VarPanelDomain]
	}
	if strings.TrimSpace(vars[tlscfg.VarDNSArgs]) == "" {
		vars[tlscfg.VarDNSArgs] = "{env." + tlscfg.VarDNSCredential + "}"
	}
	if strings.EqualFold(vars[tlscfg.VarHTTPSMode], tlscfg.HTTPSModeE2E) {
		vars[tlscfg.VarHTTPSE2EPort] = vars["LT_VHOST_HTTPS_PORT"]
	} else {
		delete(vars, tlscfg.VarHTTPSE2EPort)
	}
}

func stripScheme(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	return strings.TrimRight(v, "/")
}
