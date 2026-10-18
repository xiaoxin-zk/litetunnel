package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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
		// 客户端已经走了：磁盘不能留在新配置上，否则下一次重建容器时
		// 会突然按一份「谁也没确认过」的配置起来。
		rbErr := batch.revert()
		if rbErr != nil && !errors.Is(rbErr, errBatchCleanupPending) {
			return res, fmt.Errorf("请求在写盘后中断，且回滚磁盘失败（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", err, rbErr)
		}
		if rbErr != nil {
			// 文件已回到旧配置，只是记录没删掉：不影响下次启动，但它是一次
			// 残留，应当让管理员知道（下次启动会自动清理）。
			res.Warnings = append(res.Warnings, rbErr.Error())
		}
		return res, err
	}

	// 10) 重建容器。
	//
	// 文件都没有变化时仍然重建：.env 里的 DNS 凭据可能变了，
	// 而 compose 只有在重建容器时才会把新的环境变量带进容器。
	out, upErr := s.composeUp(ctx)
	if upErr != nil {
		return res, s.recoverFromFailedApply(ctx, batch, upErr, out)
	}

	// 容器已按新配置起来，这时才算「生效」——可以撤记录、清备份了。
	//
	// 收尾失败分两类：记录已清掉或标成 committed（只是备份没清干净）→ 记
	// warning；记录既标不成也删不掉 → 必须报 partial，因为重启时启动恢复
	// 会把磁盘回滚到旧配置，而运行中的容器仍是新版本。
	if err := batch.finalize(); err != nil {
		if errors.Is(err, errBatchRecoveryAtRisk) {
			statesCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			states := s.serviceStates(statesCtx)
			cancel()
			return res, &partialApplyError{
				msg:      fmt.Sprintf("配置与容器均已生效，但批次现场无法落定：重启可能把磁盘回滚到旧配置，需人工处理\n%v", err),
				services: states,
			}
		}
		res.Warnings = append(res.Warnings, err.Error())
	}
	res.Applied = true
	res.Validate = strings.TrimSpace(res.Validate + "\n" + out)
	res.Message = "配置已应用，caddy 与 frps 已重建"
	return res, nil
}

// partialApplyError 表示配置没有停在「全部生效」或「全部回滚」上。
//
// 单独一个类型是为了让 HTTP 层能给出结构化结果（partial + 各容器状态），
// 而不是把「现在到底是哪一版在跑」埋进一段错误文本里。
type partialApplyError struct {
	msg      string
	services []tlscfg.ServiceState
}

func (e *partialApplyError) Error() string { return e.msg }

// recoverFromFailedApply 处理「文件已换好、容器重建失败」。
//
// 目标是把磁盘与容器拉回同一个版本：先回滚文件，再按旧配置重建一次。
// 两步都成功才算真的回滚。任何一步失败都必须明确说「现在不是已知状态」，
// 并给出每个容器的实际状态——只说「重建失败」，管理员既不知道该重试
// 还是该手工修，也看不出磁盘与新配置哪个已经生效。
// rollbackTimeout 是「回滚重建」的独立预算。
//
// 必须独立：走到这里最常见的原因就是请求超时或客户端断开，那时请求的
// ctx 已经取消，用它去重建容器会立刻失败——磁盘恢复成旧配置，容器却
// 停在新配置上，正好制造出最需要避免的跨版本状态。
const rollbackTimeout = 3 * time.Minute

func (s *service) recoverFromFailedApply(reqCtx context.Context, batch *writeBatch, upErr error, upOut string) error {
	detail := strings.TrimSpace(upOut)
	if detail != "" {
		detail = "\n" + detail
	}
	// 请求被取消是「为什么走到回滚」的一部分，写进结论里，别让管理员
	// 以为是配置本身有问题。
	if err := reqCtx.Err(); err != nil {
		detail += fmt.Sprintf("\n（原请求已中断：%v；回滚使用独立预算继续执行）", err)
	}

	// 回滚阶段全程用独立预算（见 rollbackTimeout），重建与查状态共用它。
	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()

	rbErr := batch.revert()
	// 「文件已恢复、只是记录没清掉」不算回滚失败：磁盘是自洽的旧版本。
	cleanupPending := errors.Is(rbErr, errBatchCleanupPending)
	if rbErr != nil && !cleanupPending {
		states := s.serviceStates(rollbackCtx)
		return &partialApplyError{
			msg: fmt.Sprintf("容器重建失败，磁盘回滚也失败：磁盘与新容器可能都是新配置，需人工处理"+
				"\n重建错误: %v\n回滚错误: %v%s", upErr, rbErr, detail),
			services: states,
		}
	}
	note := ""
	if cleanupPending {
		note = "；批次记录未删除，重启后会自动清理"
	}

	// 文件已回到旧配置。再重建一次，尽量让容器也回到旧版本。
	if _, reErr := s.composeUp(rollbackCtx); reErr == nil {
		return fmt.Errorf("%w（磁盘与容器均已回滚到旧配置%s，可修改后重试）%s", upErr, note, detail)
	} else {
		states := s.serviceStates(rollbackCtx)
		return &partialApplyError{
			msg: fmt.Sprintf("新配置重建失败，磁盘已回滚为旧配置，但按旧配置重建也失败：容器当前版本未知"+
				"\n新配置重建错误: %v\n回滚重建错误: %v%s", upErr, reErr, detail),
			services: states,
		}
	}
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
	// manifest 是这一批的现场记录。commit 成功后仍保留在磁盘上，
	// 直到 finalize（确认生效）或 revert（撤回）把它撤掉。
	manifest batchManifest
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
	// 先把整批文件的身份落盘，再动第一个目标文件。进程内回滚只覆盖「本进程
	// 还活着」的失败；强杀或断电时，磁盘可能停在第一个文件已换新、第二个
	// 还没换的中间态，而启动清理单看某个文件的备份无法判断整批是否提交完整。
	// 有这份记录，重启后就能确定「这一批没提交完」，整批回滚到旧配置。
	m, err := b.writeManifest()
	if err != nil {
		b.discard()
		return batchManifestError(err)
	}
	b.manifest = m

	for i := range b.staged {
		st := b.staged[i]
		if err := st.commit(); err != nil {
			// 当前文件替换失败（它已尽量自行恢复），回滚前面已成功替换的文件，
			// 丢弃尚未替换的临时文件。回滚本身也失败时，磁盘可能处于新旧混合
			// 状态，必须如实上报，而不是只报「替换失败」。
			rbErr := b.rollbackCommitted()
			b.discardFrom(i)
			if rbErr != nil {
				// 保留批次记录：下次启动时由它把整批恢复回去。删掉记录等于
				// 把「磁盘可能混合」这件事藏起来。
				return fmt.Errorf("替换 %s 失败，且回滚未完成（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", st.name, err, rbErr)
			}
			b.removeManifest(m)
			return fmt.Errorf("替换 %s 失败，已回滚（磁盘仍为旧配置）: %w", st.name, err)
		}
		b.done++
	}
	// 每个文件的备份摘要此刻才齐全，补写进记录：崩溃恢复时要靠它确认
	// 「这份备份确实是当时的旧文件」，而不是一份写了一半的东西。
	b.refreshBackupSums()

	// 全部成功，但**不在这里**撤记录、清备份。
	//
	// 配置是否真的生效要等容器重建完——那一步由调用方做（见 apply 的
	// finalize 调用）。在这里清掉备份，容器重建失败时就再也回不去旧配置；
	// 而在这里清掉记录，「文件已换好、容器没起来」的中间态就少了一份说明。
	return nil
}

// finalize 在配置确认生效（容器已按新配置重建）后落定这一批。
//
// 顺序：先标记 committed，再删记录，最后清备份。
//   - 标记失败 → 保留记录与备份。下次启动看到的是「未提交」，会回滚——
//     这会把一份已经生效的配置撤回，但比「磁盘与容器都在新版本、记录却
//     指向不存在的备份」更容易收拾；
//   - 记录删失败 → 记录仍是 committed，下次启动只清理、不回滚
//     （见 recoverBatch），备份留到那时再清；
//   - 备份清理失败 → 只是残留文件，不影响任何判定。
func (b *writeBatch) finalize() error {
	if len(b.staged) == 0 {
		return nil
	}
	m := b.manifest
	m.Status = batchStatusCommitted
	if err := writeManifestFile(m); err != nil {
		// 标记写不进去（磁盘满、目录权限被改）。这时**不能**把记录留在
		// 「未提交」状态：容器已经按新配置跑起来了，下次启动按记录回滚
		// 会把磁盘退回旧配置，而容器仍是新版本——磁盘与容器分叉。
		//
		// 退而删除记录：删除比写入更可能成功（不需要新空间），而
		// 「没有记录」正是启动恢复理解的「已落定」。
		if b.removeManifest(b.manifest) {
			for _, st := range b.staged {
				st.cleanupBackup()
			}
			return fmt.Errorf("批次状态未能标记，已直接清除记录（配置与容器均已生效）: %w", err)
		}
		// 标记与删除都失败：只能如实告知。清理备份会把最后一点现场也抹掉，
		// 所以保留它们，留给人工判断。
		return fmt.Errorf("%w: 批次状态未能标记、记录也未能删除，请手动删除部署目录下的 %s 与 %s 备份: %v",
			errBatchRecoveryAtRisk, batchManifestName, backupSuffix, err)
	}
	if !b.removeManifest(m) {
		// 记录已经标成 committed，留着无害；备份也留着，等下次启动清理。
		return errors.New("配置已生效，但批次记录未能删除（下次启动会自动清理，不影响运行中的配置）")
	}
	for _, st := range b.staged {
		st.cleanupBackup()
	}
	return nil
}

// revert 把整批文件恢复成提交前的旧内容，并撤掉记录与备份。
//
// 用于「文件已经换好，但容器重建失败」：此时磁盘是新配置、容器还是旧的，
// 不做这一步就留下一个跨版本的半成品。
func (b *writeBatch) revert() error {
	if len(b.staged) == 0 {
		return nil
	}
	if err := b.rollbackCommitted(); err != nil {
		// 恢复失败：记录与备份必须留着，它们是下次启动唯一能依的现场。
		return err
	}
	if !b.removeManifest(b.manifest) {
		// 文件已经回到旧配置，但记录还在。此时**不能**清备份：
		// 下次启动会看到这份「未提交」记录，再回滚一遍——如果那次发现
		// 某个文件仍停在中间态（例如 restore 之后又被别的东西写过），
		// 备份就是唯一的材料。清掉它等于把「还能修」变成「只能手工拼」。
		//
		// 回滚本身是成功的，所以返回哨兵错误而不是普通错误：调用方要
		// 继续按旧配置重建容器，只是别把这次操作报成「磁盘还是新配置」。
		return fmt.Errorf("%w: 文件已恢复为旧配置，但批次记录未能删除（备份已保留，重启后会自动清理）",
			errBatchCleanupPending)
	}
	b.discard()
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
