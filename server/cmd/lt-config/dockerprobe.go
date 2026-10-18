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

// 本文件是 docker 可用性探测的独立单元：探测（exec.LookPath + docker info）、
// 缓存（TTL + 单飞）、把结论组装进健康响应。
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

// fillDockerHealth 把探测结论填进健康响应，并返回原始结论。
//
// 三个字段的分工必须保持（面板按它决定按钮能否点）：
//   - Docker：命令在 PATH 里；
//   - DockerReady：宿主机现在真能起容器；
//   - DockerErr：DockerReady 为假时的可读原因，供界面直接展示。
//
// DockerErr 只在未就绪时填：就绪还留着一句旧错误，会让界面显示一条吓人的
// 提示，而实际一切正常。
func (s *service) fillDockerHealth(h *tlscfg.Health) dockerProbeResult {
	res := s.dockerStatus()
	h.Docker = res.Found
	h.DockerReady = res.Ready
	if !res.Ready {
		h.DockerErr = res.Reason
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
