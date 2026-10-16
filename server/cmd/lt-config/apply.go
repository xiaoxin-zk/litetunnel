package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件是这套流程的主线：合并配置 → 渲染 → 校验 → 写盘 → 重建容器。
//
// 它只做编排，每一步的实现都在别处：
//
//	合并与派生   —— 这里的 deriveVars + envfile.go 的读写
//	变量校验     —— validate.go
//	模板渲染     —— internal/tlscfg 的 Render（与渲染脚本同一套语义）
//	容器校验     —— validate.go（用目标镜像实跑一次）
//	写盘         —— 这里的 stagedWrites + envfile.go 的两阶段提交
//	重建容器     —— compose.go

// renderAndApply 是「合并配置 → 渲染 → 校验 → 写盘 → 重建」的完整流程。
//
// 顺序不可调换：写盘必须在校验之后。先写盘再校验的话，一次笔误就能让
// 磁盘上留下一份 Caddy 拒绝加载的配置——重启 caddy 时才爆炸，
// 而那时管理员已经离开这个页面了。
func (s *service) renderAndApply(req tlscfg.RenderRequest) (tlscfg.RenderResult, error) {
	var res tlscfg.RenderResult

	// 全程串行。两个并发的 /render 会交错读 .env、写三个文件并各自触发一次
	// 容器重建，结果是磁盘上的配置可能来自两次请求的混合，而容器重建了两轮。
	// 面板通常只有一个页面在调它，但接口的安全性不该建立在「调用方克制」上。
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	env, vars, err := readEnvFile(s.paths.envFile)
	if err != nil {
		return res, fmt.Errorf("读取 %s 失败: %w", s.paths.envFile, err)
	}

	// 1) 合并面板覆盖值。白名单之外的键一律拒绝，而不是静默忽略：
	//    静默忽略会让面板以为「我改了」而实际没改。
	for _, k := range sortedKeys(req.Vars) {
		if !tlscfg.IsOverridable(k) {
			return res, fmt.Errorf("不允许覆盖变量 %s", k)
		}
		vars[k] = strings.TrimSpace(req.Vars[k])
	}
	// 留一条不含密钥的快照：事后回答「当时到底下发了什么」时，
	// 唯一的依据就是这行日志与磁盘上的文件。
	log.Printf("[lt-config] 面板下发的变量: %v", tlscfg.Redact(req.Vars))

	// 2) 派生值，与 deploy/scripts/render.* 保持一致。
	deriveVars(vars)

	// 3) 校验合并后的变量。这一步在渲染之前，报错信息才能指向具体字段。
	if err := s.validateVars(vars, &res); err != nil {
		return res, err
	}

	// 4) 渲染
	caddyTpl, err := os.ReadFile(s.paths.caddyTpl)
	if err != nil {
		return res, fmt.Errorf("读取 Caddyfile 模板失败: %w", err)
	}
	frpsTpl, err := os.ReadFile(s.paths.frpsTpl)
	if err != nil {
		return res, fmt.Errorf("读取 frps.toml 模板失败: %w", err)
	}
	caddyText, err := tlscfg.Render(string(caddyTpl), vars)
	if err != nil {
		return res, fmt.Errorf("渲染 Caddyfile 失败: %w", err)
	}
	frpsText, err := tlscfg.Render(string(frpsTpl), vars)
	if err != nil {
		return res, fmt.Errorf("渲染 frps.toml 失败: %w", err)
	}

	// 5) 校验：用将要上线的那个镜像，而不是随便一个。
	//    官方镜像没有 dns 插件，拿它校验「带 DNS Challenge 的自建镜像配置」
	//    会误报 unrecognized directive: dns。
	caddyImage := s.effectiveCaddyImage(vars)
	validateOut, err := s.validateCaddy(caddyText, caddyImage, vars)
	if err != nil {
		return res, err
	}
	res.Validate = validateOut
	if s.validateFrps {
		frpsOut, err := s.validateFrpsConfig(frpsText)
		if err != nil {
			return res, err
		}
		res.Validate = strings.TrimSpace(res.Validate + "\n" + frpsOut)
	}

	// 6) 组装待写产物。走到这里为止，磁盘上的文件一个都没动。
	writes := []pendingWrite{
		// Caddyfile 里只有域名与 {env.*} 引用，凭据在容器环境变量里。
		{name: "Caddyfile", path: s.paths.caddyOut, content: caddyText, mode: modeConfig},
		// frps.toml 里有 frps 全局 token 与管理 API 密码，必须只有属主可读。
		{name: "frps.toml", path: s.paths.frpsOut, content: frpsText, mode: modeSecret},
	}

	// 7) 同步 .env：compose 靠它把 DNS 凭据注入 Caddy 容器。
	if req.WriteEnv {
		for _, k := range sortedKeys(req.Vars) {
			if env.set(k, vars[k]) {
				res.EnvUpdated = append(res.EnvUpdated, k)
			}
		}
		writes = append(writes, pendingWrite{
			name: ".env", path: s.paths.envFile, content: env.content(), mode: modeSecret,
		})
	}

	// 8) 两阶段提交：候选内容全部就绪后才逐个替换。
	batch, err := prepareWrites(writes)
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, batch.warn...)
	if err := batch.commit(); err != nil {
		return res, err
	}
	res.Changed = sortedChanged(batch.changed)

	// 9) 应用
	if req.Apply {
		if !s.allowApply {
			return res, errors.New("本服务以只渲染模式启动（LT_CFG_APPLY=false），配置已生成但未重建容器")
		}
		// 文件都没有变化时仍然重建：.env 里的 DNS 凭据可能变了，
		// 而 compose 只有在重建容器时才会把新的环境变量带进容器。
		out, err := s.composeUp()
		if err != nil {
			return res, err
		}
		res.Applied = true
		res.Validate = strings.TrimSpace(res.Validate + "\n" + out)
		res.Message = "配置已应用，caddy 与 frps 已重建"
	} else {
		res.Message = "配置已生成并通过校验（未应用）"
	}
	return res, nil
}

// deriveVars 计算由其他变量派生的值，规则与渲染脚本一致。
//
// 两边必须同步：面板保存的是「域名与证书」这几项，而模板要的是它们派生出来的
// 一串值（站点地址、ACME 邮箱、dns 参数、端到端入口端口）。手工跑脚本与从
// 后台下发走的是同一套规则，才不会出现「脚本生成的对、后台生成的错」。
func deriveVars(vars map[string]string) {
	// 站点地址：Caddy 需要一个不带 scheme 的裸域名。
	if v := stripScheme(vars[tlscfg.VarUserPublicURL]); v != "" {
		vars[tlscfg.VarPanelDomain] = v
	}
	if vars[tlscfg.VarACMEEmail] == "" && vars[tlscfg.VarPanelDomain] != "" {
		vars[tlscfg.VarACMEEmail] = "admin@" + vars[tlscfg.VarPanelDomain]
	}
	// 凭据只经环境变量进容器：Caddyfile 里写 {env.X}，值不进文件、不进日志。
	if strings.TrimSpace(vars[tlscfg.VarDNSArgs]) == "" {
		vars[tlscfg.VarDNSArgs] = "{env." + tlscfg.VarDNSCredential + "}"
	}
	// 端到端 HTTPS 模式下，HTTPS 隧道的公网入口就是 frps 的 vhostHTTPSPort。
	// 模板用这个派生变量做条件块（模板的条件语法只支持「非空则保留」）。
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

// pendingWrite 是一个待写入的产物。
type pendingWrite struct {
	name    string
	path    string
	content string
	mode    os.FileMode
}

// writeBatch 是一次「多文件更新」的候选集合：候选内容都已经落到临时文件，
// 但目标文件一个都还没被替换。
type writeBatch struct {
	staged  []*stagedFile
	changed map[string]bool
	warn    []string
	// done 是已成功替换的文件数，失败时用于说清边界。
	done int
}

// prepareWrites 比较内容、准备候选项。
//
// 内容一致的产物不准备替换，但仍会把权限纠正到期望值：早期版本给 frps.toml
// 与 .env 写过 0644，只比较内容就跳过的话，那份宽松权限会一直留在磁盘上。
// 权限被改动过会记进 warn——这不是「配置变了」，但管理员应该知道。
func prepareWrites(writes []pendingWrite) (*writeBatch, error) {
	b := &writeBatch{changed: map[string]bool{}}
	for _, w := range writes {
		if old, err := os.ReadFile(w.path); err == nil && string(old) == w.content {
			fixed, err := ensureMode(w.path, w.mode)
			if err != nil {
				b.discard()
				return nil, fmt.Errorf("检查 %s 的权限失败: %w", w.name, err)
			}
			if fixed {
				b.warn = append(b.warn,
					fmt.Sprintf("%s 的内容没变，但权限已收紧为 %#o", w.name, w.mode.Perm()))
			}
			continue
		}
		st, err := stageFile(w.name, w.path, w.content, w.mode)
		if err != nil {
			b.discard()
			return nil, fmt.Errorf("准备写入 %s 失败: %w", w.name, err)
		}
		b.staged = append(b.staged, st)
		b.changed[w.name] = true
	}
	return b, nil
}

// commit 逐个替换目标文件。
//
// 刻意不做回滚：回滚得先备份旧内容，而多一份「磁盘上到底是新是旧」的疑问
// 比多写一次更难收拾。中途失败时如实报出边界——哪些文件已经替换、哪些还没
// 动过——管理员再点一次下发即可收敛。
func (b *writeBatch) commit() error {
	for i, st := range b.staged {
		if err := st.commit(); err != nil {
			b.discardFrom(i)
			return fmt.Errorf("替换 %s 失败（已替换 %d 个文件，其余未改动）: %w", st.name, b.done, err)
		}
		b.done++
	}
	return nil
}

// discard 放弃整批候选内容。
func (b *writeBatch) discard() { b.discardFrom(0) }

func (b *writeBatch) discardFrom(i int) {
	for _, st := range b.staged[i:] {
		st.discard()
	}
}
