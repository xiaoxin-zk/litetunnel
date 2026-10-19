package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件是 docker 可用性探测的独立单元：探测（exec.LookPath + docker info +
// docker compose version）、缓存（TTL + 单飞）、把结论组装进健康响应。
//
// # 为什么单独拆出来
//
// 「docker 命令在」与「宿主机能起容器」是两件事，而面板的安全边界完全建立在
// 这个区分上：命令在但 daemon 不可用时，面板必须只允许「保存」、不允许
// 「校验/应用」。这段判定有三个容易各自跑偏的部分——探测口径、缓存与并发、
// 字段组装——放在 handlers.go 里时，它们与 HTTP 状态码、部署目录检查混在一起，
// 改动任意一处都得重读整段请求处理逻辑。
//
// 拆开之后 handlers.go 只负责「把结论填进 Health」，这里只负责「结论是什么」。
// 测试仍然通过 service.dockerProbeFn 注入替身（见 health_test.go），不依赖
// 本机是否装了 docker。
//
// # 为什么还要探测 compose
//
// 本服务重建容器**只用** `docker compose up`（见 compose.go），从不直接
// `docker run`。而「daemon 能用」与「compose 能用」是两层：docker 装上了、
// daemon 起来了，但 compose 插件没装（或只装了 V1 的独立 docker-compose，
// 或 docker 版本太老不认 `compose` 子命令）时，`docker info` 照样成功。
//
// 早期只探 docker info，于是面板一路放行到「保存并应用」，失败发生在文件
// 已经写盘之后——配置与容器分处两个版本，正是本文件存在的意义所在。
// 所以这里把 compose 也当成探测项，并**单独**报告（Health.ComposeReady）：
// 「daemon 不可用」要去启动 docker，「compose 缺失」要去装插件或 compose
// 包，两者的处置方式不同，界面文案也不该混成一句。

// dockerProbeTimeout 是一次 docker 可用性探测的时间上限。
//
// 必须压得很短：/health 会被面板与部署脚本高频轮询，而 daemon 不通时
// docker CLI 自己可能要等十几秒（DOCKER_HOST 指向不响应的 socket、宿主
// 磁盘 hang）。没有上限的话，一次卡住就把探测锁与请求一起拖住，健康检查
// 从「报告状态」变成「又一个超时」。
const dockerProbeTimeout = 2 * time.Second

// composeProbeTimeout 是一次 compose 可用性探测的时间上限。
//
// 比 dockerProbeTimeout 更短是有意的：一次健康检查最多跑两个探测
// （`docker info` + `docker compose version`），而它们在同一把探测锁下
// 串行执行——各给 2 秒的话，最坏情况一次 /health 会把锁占住 4 秒，面板与
// 部署脚本的轮询一起排在后面。压到 1.5 秒后，整次探测的上界是 3.5 秒。
//
// 敢压短的事实依据：`docker compose version` 只读本地版本信息，不连 daemon，
// 正常几十毫秒返回；而真正卡住的原因（docker 二进制 hang、插件解析卡在
// 不可达的路径上）本来就没有「再等一会儿就好了」的可能。
const composeProbeTimeout = 1500 * time.Millisecond

// dockerProbeTTL 是探测结果的缓存时长。
//
// 每次请求都起一个 docker 进程是不能接受的：每次探测都要连一次 daemon
// （unix socket / Windows 命名管道），部署脚本轮询时那是稳定的进程风暴，
// 而 docker 探测本身还会占住 daemon 的一次连接。现在一次探测要起**两个**
// 进程，缓存因此更重要。
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
	//
	// 它的语义**刻意**保持在「daemon 可用」这一层，不含 compose：
	// 已有的界面与脚本按它判断「能不能起容器」，把 compose 折进来会让
	// 「装个插件」变成「Docker 不可用」。compose 单独由 ComposeReady 报告。
	Ready bool
	// Reason 是 Ready 为假时的可读中文原因。
	Reason string
	// ComposeReady 表示 compose 可用：daemon 可用**且** `docker compose`
	// （或独立 docker-compose）能跑。
	//
	// 恒有 ComposeReady ⇒ Ready，反之不成立。
	ComposeReady bool
	// ComposeReason 是 ComposeReady 为假、但 daemon 可用时的可读原因。
	// daemon 本身就不可用时留空——那时 ComposeReady 为假只是连带结果，
	// 再说一句「compose 不可用」只会把管理员引去装插件。
	ComposeReason string
}

// composeProbeResult 是「compose 能不能用」的结论。
type composeProbeResult struct {
	Ready  bool
	Reason string
}

// dockerProbeCache 缓存探测结果，并保证同一时刻只有一次探测在跑。
//
// 用互斥锁而不是放开并发：并发请求同时过期时各自起 docker 进程毫无
// 意义，还会在 daemon 卡顿时叠加等待。持有锁期间其余请求直接排队，拿到
// 的是这一次的结果。
//
// 缓存的是一个**整体**结论（daemon + compose）：两者都在锁内完成，所以
// 「一次健康检查只跑一轮进程」这条性质对新增的 compose 探测同样成立。
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
//
// 两级替身钩子：
//   - dockerProbeFn 覆盖**整份**结论（含 compose 字段），用于只关心
//     「结论如何影响 Health」的用例；
//   - composeProbeFn 只替换 compose 那一段，让真实 probeDockerHost 与
//     「daemon 可用 → 接着探 compose」这条串接逻辑也能被测到，而不依赖
//     本机装没装 compose。
func (s *service) probeDocker() dockerProbeResult {
	if s.dockerProbeFn != nil {
		return s.dockerProbeFn()
	}
	return composeAfterDocker(probeDockerHost(), s.probeCompose)
}

// composeAfterDocker 在 daemon 可用的前提下补上 compose 结论。
//
// 单独抽成纯函数（把 compose 探测作为参数传进来）是为了让这条串接逻辑
// 可测：daemon 不可用时**不允许**再探 compose（多起一个进程只是为了报一个
// 连带为假的状态），而这条「不调用」的性质只能靠传入一个会计数的
// probeCompose 来验证——直接跑 probeDocker 会真的在本机起 docker 进程。
func composeAfterDocker(res dockerProbeResult, probeCompose func() composeProbeResult) dockerProbeResult {
	if !res.Ready {
		// daemon 都不通：ComposeReady 保持 false，ComposeReason 留空。
		// 留空是有意的——界面据此把告警写成「Docker 不可用」而不是
		// 「compose 不可用」，否则管理员会去装一个装不上的插件。
		return res
	}
	cres := probeCompose()
	res.ComposeReady = cres.Ready
	res.ComposeReason = cres.Reason
	return res
}

// probeCompose 探测 compose 是否可用，测试里可替换。
func (s *service) probeCompose() composeProbeResult {
	if s.composeProbeFn != nil {
		return s.composeProbeFn()
	}
	return probeComposeHost()
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
	// 这里不再提 compose：compose 有自己的探测与自己的字段（见
	// probeComposeHost）。把两种原因写在一句里，会让「缺插件」这种可以
	// 装一下就好问题看起来像「Docker 整个不可用」。
	return dockerProbeResult{Found: true, Reason: "docker 命令存在，但宿主机不可用（daemon 未启动或无 socket 权限）：" +
		truncateRunes(text, 200)}
}

// probeComposeHost 判断本机能不能执行 compose 命令。
//
// 两种安装形式都要认：
//
//   - `docker compose`：Compose V2，随 docker CLI 以插件形式发布（现主流）；
//   - `docker-compose`：V1 的独立二进制，以及部分发行版的包名。
//
// 只认插件形式会把「装了 docker-compose 的老部署」误报成不可用；只认独立
// 二进制则会把现主流的部署误报。先试插件（新部署的默认形态），失败再退回
// 独立二进制——两次探测都在 composeProbeTimeout 内完成，且**不连 daemon**，
// 所以不会因为 daemon 忙而变慢。
func probeComposeHost() composeProbeResult {
	pluginOut, pluginErr := runVersionProbe("docker", "compose", "version")
	if pluginErr == nil {
		return composeProbeResult{Ready: true}
	}

	// 退回 V1 的独立二进制。LookPath 失败说明它也没装，不必再起进程。
	if path, err := exec.LookPath("docker-compose"); err == nil && path != "" {
		if _, err := runVersionProbe(path, "version"); err == nil {
			return composeProbeResult{Ready: true}
		}
	}

	detail := pluginOut
	if detail == "" {
		detail = pluginErr.Error()
	}
	return composeProbeResult{Reason: "docker compose 不可用（插件与独立 docker-compose 都没能跑起来）：" +
		"校验与重建容器都要用它，请安装 compose 插件（docker-compose-plugin）或 docker-compose；" +
		"docker compose version 的输出：" + truncateRunes(detail, 200)}
}

// runVersionProbe 在 composeProbeTimeout 内跑一次版本探测，返回输出与错误。
//
// 单独一个函数而不是内联：两个候选命令（插件 / 独立二进制）都要用同一套
// 超时与截断口径，写两遍必然有一处先被改歪。
func runVersionProbe(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), composeProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return truncateRunes(text, 200),
				fmt.Errorf("%s %s 在 %s 内没有响应", bin, strings.Join(args, " "), composeProbeTimeout)
		}
		if text == "" {
			return "", err
		}
		return truncateRunes(text, 200), err
	}
	return text, nil
}

// fillDockerHealth 把探测结论填进健康响应，并返回原始结论。
//
// 字段分工必须保持（面板按它决定按钮能否点）：
//   - Docker：命令在 PATH 里；
//   - DockerReady：宿主机现在真能起容器（daemon 可用）；
//   - DockerErr：DockerReady 为假时的可读原因；
//   - ComposeReady：daemon 可用**且** compose 可用（应用类操作的真正门槛）；
//   - ComposeErr：ComposeReady 为假、但 daemon 可用时的可读原因。
//
// Err 只在对应 Ready 为假时填：就绪还留着一句旧错误，会让界面显示一条吓人
// 的提示，而实际一切正常。ComposeErr 在 daemon 就不可用时保持为空——那时
// ComposeReady 为假是连带结果，多给一句话只会把管理员引去装插件。
func (s *service) fillDockerHealth(h *tlscfg.Health) dockerProbeResult {
	res := s.dockerStatus()
	h.Docker = res.Found
	h.DockerReady = res.Ready
	if !res.Ready {
		h.DockerErr = res.Reason
	}
	h.ComposeReady = res.ComposeReady
	if !res.ComposeReady {
		h.ComposeErr = res.ComposeReason
	}
	return res
}

// truncateRunes 截断过长的命令输出，避免整段 docker 报错灌进健康检查响应。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
