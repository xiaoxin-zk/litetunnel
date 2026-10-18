package main

import (
	"context"
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
func (s *service) renderAndApply(ctx context.Context, req tlscfg.RenderRequest) (tlscfg.RenderResult, error) {
	var res tlscfg.RenderResult

	// 全程串行。两个并发的 /render 会交错读 .env、写三个文件并各自触发一次
	// 容器重建，结果是磁盘上的配置可能来自两次请求的混合，而容器重建了两轮。
	// 面板通常只有一个页面在调它，但接口的安全性不该建立在「调用方克制」上。
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	env, vars, err := readEnvFile(s.paths.envFile)
	if err != nil {
		return res, internalError(fmt.Errorf("读取 %s 失败: %w", s.paths.envFile, err))
	}

	// 1) 合并面板覆盖值。白名单之外的键一律拒绝，而不是静默忽略：
	//    静默忽略会让面板以为「我改了」而实际没改。
	for _, k := range sortedKeys(req.Vars) {
		if !tlscfg.IsOverridable(k) {
			return res, fmt.Errorf("不允许覆盖变量 %s", k)
		}
		v := strings.TrimSpace(req.Vars[k])
		// 值会被拼成 .env 的一行（见 envfile.go 的 set）。带换行就能追加额外的
		// 键——包括白名单之外的 LT_CADDY_IMAGE。面板侧已经拒绝，这里是第二道：
		// helper 是独立的信任边界，不能假定调用方一定校验过。
		if tlscfg.HasControlChars(v) {
			return res, fmt.Errorf("变量 %s 的值含有换行或其他控制字符：写进 .env 会变成额外的配置行", k)
		}
		vars[k] = v
	}
	// 留一条不含密钥的快照：事后回答「当时到底下发了什么」时，
	// 唯一的依据就是这行日志与磁盘上的文件。
	log.Printf("[lt-config] 面板下发的变量: %v", tlscfg.Redact(req.Vars))

	// 2) 派生值，与 deploy/scripts/render.* 保持一致。
	deriveVars(vars)

	// 2.5) 校验用的镜像必须就是 Compose 会用的那个。
	//
	// compose 的写法是 image: ${LT_CADDY_IMAGE:-caddy:2-alpine}，读的是 .env；
	// 而 LT_CADDY_IMAGE 不在面板可覆盖的白名单里，所以它只可能来自 .env 本身。
	// 若 LT_CFG_CADDY_IMAGE 指定了另一个镜像，这次「校验通过」就只对那个镜像
	// 成立——官方镜像没有 dns 插件、自建镜像有，两者的指令集不同，校验等于
	// 自我安慰。宁可当场报错，也不要留下「校验过的东西不是要上线的东西」。
	caddyImage := s.effectiveCaddyImage(vars)
	// 必须逐字比较：镜像引用区分大小写，:Release 与 :release 可能是
	// 两个不同的 tag。用 EqualFold 的话，「校验镜像 == Compose 镜像」
	// 会放过仅大小写不同的错配——校验又在为另一个镜像背书了。
	// 两边都来自 .env / 配置的原始写法，比较的就是管理员填的那串字符。
	if composeImage := tlscfg.ComposeCaddyImage(vars); caddyImage != composeImage {
		return res, fmt.Errorf(
			"校验用的 Caddy 镜像（%s）与 Compose 实际会使用的镜像（%s）不一致："+
				"请让 LT_CFG_CADDY_IMAGE 与 .env 的 LT_CADDY_IMAGE 相同，或取消前者",
			caddyImage, composeImage)
	}

	// 3) 校验合并后的变量。这一步在渲染之前，报错信息才能指向具体字段。
	if err := s.validateVars(vars, &res); err != nil {
		return res, err
	}

	// 4) 渲染
	caddyTpl, err := os.ReadFile(s.paths.caddyTpl)
	if err != nil {
		return res, internalError(fmt.Errorf("读取 Caddyfile 模板失败: %w", err))
	}
	frpsTpl, err := os.ReadFile(s.paths.frpsTpl)
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

	// 5) 校验：用将要上线的那个镜像（已在上一步确认与 Compose 一致）。
	//    官方镜像没有 dns 插件，拿它校验「带 DNS Challenge 的自建镜像配置」
	//    会误报 unrecognized directive: dns。
	validateOut, err := s.validateContainers(ctx, caddyText, caddyImage, frpsText, vars)
	if err != nil {
		return res, err
	}
	res.Validate = validateOut

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

	// 8) 「只校验不应用」：到此为止磁盘上一个文件都没动。
	//
	// 这不是保守，是必须：这三个文件是**容器直接挂载**的活动配置
	// （deploy/docker-compose.yml 挂进 caddy 与 frps，restart 策略是
	// unless-stopped）。校验阶段把它们改掉，之后宿主机或容器只要重启一次，
	// 这份「还没应用」的新配置就会真的生效——而面板侧记录的状态仍是上一份，
	// 两边对不上，也没有任何地方会提示。
	if !req.Apply {
		res.Changed = pendingChanges(writes)
		res.Message = "配置已生成并通过校验（未写入、未应用）"
		return res, nil
	}
	if !s.allowApply {
		// 这个检查必须放在写盘**之前**：放在后面的话，「只渲染模式」同样会
		// 把活动文件改掉，与上面那段注释说的是同一件事。
		return res, errors.New("本服务以只渲染模式启动（LT_CFG_APPLY=false），配置未写入、也未重建容器")
	}

	// 校验（可能跑了 docker）结束后、写盘前再确认一次请求仍在：校验耗时可能
	// 让浏览器/代理超时断开，此时继续写盘会留下「磁盘新、容器旧」的半套状态。
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// 9) 两阶段提交：候选内容全部就绪后才逐个替换。
	batch, err := prepareWrites(writes)
	if err != nil {
		return res, internalError(err)
	}
	res.Warnings = append(res.Warnings, batch.warn...)
	if err := batch.commit(); err != nil {
		return res, internalError(err)
	}
	res.Changed = sortedChanged(batch.changed)

	// 写盘完成、重建容器前再确认一次：避免「磁盘新、容器旧」的中间态。
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// 10) 重建容器。
	//
	// 文件都没有变化时仍然重建：.env 里的 DNS 凭据可能变了，
	// 而 compose 只有在重建容器时才会把新的环境变量带进容器。
	out, err := s.composeUp(ctx)
	if err != nil {
		return res, err
	}
	res.Applied = true
	res.Validate = strings.TrimSpace(res.Validate + "\n" + out)
	res.Message = "配置已应用，caddy 与 frps 已重建"
	return res, nil
}

// pendingChanges 列出「如果应用，会变化哪些文件」，全程不碰磁盘。
//
// 「保存并校验」也要给出与「应用」一致的反馈（哪些文件会变），但它的语义
// 是只读的，所以这里只比较内容。
func pendingChanges(writes []pendingWrite) []string {
	var names []string
	for _, w := range writes {
		old, err := os.ReadFile(w.path)
		if err == nil && string(old) == w.content {
			continue
		}
		names = append(names, w.name)
	}
	return names
}

// deriveVars 计算由其他变量派生的值，规则与渲染脚本一致。
//
// 两边必须同步：面板保存的是「域名与证书」这几项，而模板要的是它们派生出来的
// 一串值（站点地址、ACME 邮箱、dns 参数、端到端入口端口）。手工跑脚本与从
// 后台下发走的是同一套规则，才不会出现「脚本生成的对、后台生成的错」。
func deriveVars(vars map[string]string) {
	// 站点地址：Caddy 需要一个不带 scheme 的裸域名；协议单独派生。
	//
	// 没有域名证书的部署用 http:// 起站点，因此协议不能硬编码成 https。
	// HSTS 只在 HTTPS 下开启：HTTP 站点发送它会让浏览器强制升级到 https。
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

// commit 逐个替换目标文件，失败时整体回滚。
//
// 三个文件互相引用（Caddyfile 的域名要与 frps.toml 的 subDomainHost 一致，
// .env 的凭据要被 Caddyfile 的 {env.X} 取到），必须要么全换成新的、要么全
// 保持旧的。逐个替换到一半失败就会留下新旧混合——那份配置要到下次容器重建
// 才以错误形式爆炸。所以每个文件替换前先备份旧内容（见 stagedFile.commit），
// 失败时把已替换的文件恢复，最终磁盘回到「全部旧配置」。
func (b *writeBatch) commit() error {
	for i := range b.staged {
		st := b.staged[i]
		if err := st.commit(); err != nil {
			// 当前文件替换失败（它已尽量自行恢复），回滚前面已成功替换的文件，
			// 丢弃尚未替换的临时文件。回滚本身也失败时，磁盘可能处于新旧混合
			// 状态，必须如实上报，而不是只报「替换失败」。
			rbErr := b.rollbackCommitted()
			b.discardFrom(i)
			if rbErr != nil {
				return fmt.Errorf("替换 %s 失败，且回滚未完成（磁盘可能处于新旧混合状态）: %v；回滚错误: %w", st.name, err, rbErr)
			}
			return fmt.Errorf("替换 %s 失败，已回滚（磁盘仍为旧配置）: %w", st.name, err)
		}
		b.done++
	}
	// 全部成功：清掉备份。
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	return nil
}

// rollbackCommitted 把已成功替换的文件恢复到备份的旧内容，返回恢复过程中
// 收集到的所有错误（nil 表示全部恢复成功）。
func (b *writeBatch) rollbackCommitted() error {
	var failures []string
	for i := 0; i < b.done; i++ {
		if err := b.staged[i].restore(); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", b.staged[i].name, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
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
