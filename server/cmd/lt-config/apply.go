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
//	写盘         —— config_txn.go 的两阶段提交（回滚见 config_txn_rollback.go，
//	                批次记录见 batch.go，单文件替换见 envfile.go）
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
	// TryLock 而不是 Lock：一次应用可能跑十几分钟（镜像校验 + 重建 +
	// 稳定检查），排队会让第二个请求在前端超时之后才开始改盘，形成「第一个
	// 还在写、第二个已经重试」的叠加。忙就明确拒绝，由调用方稍后重试。
	if !s.applyMu.TryLock() {
		return res, errApplyBusy
	}
	defer s.applyMu.Unlock()

	// 丢掉上一次请求遗留的警告：它们已经随那次响应返回过（或那次请求
	// 根本没走到校验阶段），不能在这一次的响应里重复出现。
	_ = s.takeWarns()

	// 启动时就有目录没能自动收敛：那里的批次记录与备份是唯一还能修复磁盘的
	// 东西，继续写盘会把它们覆盖掉。拒绝执行，由管理员先确认现场（见
	// dirtySceneError）。这一步刻意放在最前面且**不**自动清理——自动清理
	// 正是这里最不该做的事。
	if dir := s.dirtyDir(); dir != "" {
		return res, s.dirtySceneError(dir)
	}

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
	// 模板同样走统一读取策略（大小上限 + 只接受普通文件）：模板损坏时
	// 应当是一条明确的错误，而不是渲染出一份半截配置再让 Caddy 拒绝加载。
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

	// 5) 校验：用将要上线的那个镜像（已在上一步确认与 Compose 一致）。
	//    官方镜像没有 dns 插件，拿它校验「带 DNS Challenge 的自建镜像配置」
	//    会误报 unrecognized directive: dns。
	validateOut, err := s.validateContainers(ctx, caddyText, caddyImage, frpsText, vars)
	if err != nil {
		return res, err
	}
	res.Validate = validateOut
	// 校验阶段的非致命问题（例如临时目录清理失败，其中可能含凭据）
	// 必须随本次响应回到面板，而不是只留在日志里。
	res.Warnings = append(res.Warnings, s.takeWarns()...)

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
	if req.Apply && !req.WriteEnv {
		return res, errors.New("Apply=true 必须同时 WriteEnv=true：否则模板文件与容器读取的 .env 会不一致")
	}
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
		return res, s.commitFailure(err)
	}
	res.Changed = sortedChanged(batch.changed)

	// 内容和权限都没有变化时不必重建容器。
	//
	// 重复点「保存并应用」、或只纠正了权限，重建一次就是一次真实的连接
	// 中断（caddy 与 frps 都会重启）。此前无条件 up --force-recreate，
	// 把这个本该免费的操作变成了有代价的。
	//
	// 「凭据可能变了所以总要重建」不成立：凭据写在 .env 里，内容变了就会
	// 出现在 Changed 中并走下面的重建。
	if len(batch.changed) == 0 {
		// 权限变化不影响容器运行时（.env 内容没变就不会换环境变量），
		// 因此这里只看内容。重建一次就是 caddy 与 frps 各断一次。
		res.Applied = false
		res.Message = "配置内容无变化，未重建容器"
		return res, nil
	}

	// 写盘完成、重建容器前再确认一次：避免「磁盘新、容器旧」的中间态。
	if err := ctx.Err(); err != nil {
		// 客户端已经走了：磁盘不能留在新配置上，否则下一次重建容器时
		// 会突然按一份「谁也没确认过」的配置起来。
		rbErr := batch.revert()
		if rbErr != nil && !errors.Is(rbErr, errBatchCleanupPending) {
			return res, fmt.Errorf("请求在写盘后中断，且回滚磁盘失败（已保留批次记录，重启后按批次恢复）: %v；回滚错误: %w", err, rbErr)
		}
		if rbErr != nil {
			// 磁盘已经回到旧配置，但记录没能删掉。它不能只当一条 warning：
			// 下次启动会按这条「未提交」记录再处理一遍整批文件，与管理员
			// 此后的手工修改打架。登记阻断，避免本进程继续写盘覆盖现场。
			s.registerDirtyScene()
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("配置已回滚为旧配置，但批次记录未清理：重启时恢复逻辑会再按它处理一遍整批文件，需人工确认后清理\n%v", rbErr))
		}
		return res, err
	}

	// 10) 重建容器。
	//
	// 文件都没有变化时仍然重建：.env 里的 DNS 凭据可能变了，
	// 而 compose 只有在重建容器时才会把新的环境变量带进容器。
	//
	// 这里不再复用 /health 的 docker 探测结论：那是一次 12 秒 TTL 的缓存，
	// 最多只会过时十几秒，却会在这个「已经开始写盘」的关键点上把「宿主机
	// 到底能不能用」的判定建立在一个可能过期的观察上——探测说可用而 daemon
	// 刚挂掉，等于白写一遍盘。真正的权威是 composeUp：它按 hostError 给出
	// 「docker 宿主机不可用」的中文原因，并驱动下面的回滚。探测的用途是让
	// 管理员在**点应用之前**看到宿主机状态（见 handlers.go 的 handleHealth），
	// 两者分工就是「提前告知」与「实际执行」。
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
			// 这是运行过程中产生的脏现场：即使当前进程还没重启，后续
			// 请求也不能再覆盖 manifest/备份。启动时阻断只是兜底。
			s.registerDirtyScene()
			statesCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			states, stateErr := s.serviceStates(statesCtx)
			cancel()
			if stateErr != nil {
				states = nil
			}
			return res, &partialApplyError{
				msg:      fmt.Sprintf("配置与容器均已生效，但批次现场无法落定：重启可能把磁盘回滚到旧配置，需人工处理\n%v", err),
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

// partialApplyError 表示配置没有停在「全部生效」或「全部回滚」上。
//
// errApplyBusy 表示另一个配置应用还没结束。
//
// 单独一个哨兵而不是复用通用错误：调用方要据此返回 409（等等再试），
// 而不是 422/500（改配置/查服务）。
var errApplyBusy = errors.New("另一个配置应用正在进行，请等待它结束后重试")

// 单独一个类型是为了让 HTTP 层能给出结构化结果（partial + 各容器状态），
// 而不是把「现在到底是哪一版在跑」埋进一段错误文本里。
type partialApplyError struct {
	msg      string
	services []tlscfg.ServiceState
	// servicesErr 是「各容器实际状态」读取失败的原因。必须与「读到空列表」
	// 区分：读取失败时不能让人以为容器都不存在。
	servicesErr error
	// cause 保留原始错误链。
	//
	// 这个类型是给 HTTP 层用的「结构化结果」，不是普通的包装错误：它自己
	// 只带一句给人看的话。若把底层错误丢掉，调用方就再也没法用
	// errors.Is 认出 errBatchCleanupPending / errBatchRecoveryAtRisk 这类
	// 哨兵——「现场未清理」与「现场无法落定」的处理方式完全不同，靠匹配
	// 错误文本去区分是最不可靠的做法。
	cause error
}

func (e *partialApplyError) Error() string { return e.msg }

// Unwrap 暴露原始错误，让 errors.Is / errors.As 能穿过结构化结果继续下探。
func (e *partialApplyError) Unwrap() error { return e.cause }

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
		// 记录留在磁盘上，而且状态仍是「未提交」：下一次启动不会只是顺手
		// 清理，而是按这条记录把整批文件再回滚一次。管理员在这之后手工改好
		// 的配置会被它当成要撤掉的现场，所以必须登记运行时阻断——本进程也
		// 不能再写盘，否则同样会与那份现场互相覆盖。措辞上不能说成「重启后
		// 会自动清理」，那会让管理员以为可以放着不管。
		s.registerDirtyScene()
		note = "；但批次记录未清理，重启后恢复逻辑会按它再回滚一遍整批文件（可能覆盖此后的手工修改），需人工确认后清理"
	}

	// 文件已回到旧配置。再重建一次，尽量让容器也回到旧版本。
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
