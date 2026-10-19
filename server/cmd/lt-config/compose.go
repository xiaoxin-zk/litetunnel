package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件是**Compose 执行器**：本服务唯一会起容器的地方。
//
// 单独成文件是为了让「本服务到底能动宿主机的什么」一目了然：
// 只有这里能起容器，而它只认一个 compose 文件与两个写死的服务名。
//
// # 各部分在哪
//
//	docker_exec.go —— 怎么调 docker、调不动时算哪一类错误
//	本文件          —— 用 compose 做什么：重建、核对状态、读状态
//	dockerprobe.go —— 宿主机「能不能用」（只读探测，不改变任何状态）
//
// 拆开的理由：前者的正确性只关乎「命令跑没跑起来、错误归哪一类」，后者关乎
// 「重建什么、怎么确认它真的起来了」。混在一起时，改一处错误分类就得重读
// 整段 compose 逻辑。

// dockerTimeout 覆盖一次 docker 调用的最长时间。
// 校验要起一个临时容器（首次可能要拉镜像），重建容器也要几秒到几十秒。
const dockerTimeout = 3 * time.Minute

// composeServices 是本服务唯一会动的两个容器。
//
// 刻意写死：面板不发服务名，也就不存在「顺手把数据库容器重建掉」这种可能。
// panel 自身不在其中——它的 .env 里也有 DNS 凭据，但它不需要重启。
var composeServices = []string{"caddy", "frps"}

// composeUp 重建 caddy 与 frps。
//
// 用 up -d 而不是 restart：DNS 凭据等环境变量来自 .env 的插值，
// 只有重建容器才会带上新值；而 restart 只是把旧容器的进程重启一遍。
// 不变的服务（panel）通过 --no-deps 与显式服务名排除在外。
//
// 必须带 --force-recreate：Caddyfile 与 frpc.toml 是以 bind mount 挂进去的，
// 改的是**挂载的文件内容**；而 compose 判断「要不要重建」只看服务定义，
// 文件内容变了它照样认为无事发生，up -d 直接成功返回。少了这个参数就会出现
// 「接口回 Applied=true，容器里跑的还是旧配置」——最坏的一种失败：所有人
// 都以为改完了。
//
// 重建之后还要核对容器确实在运行：compose up 的成功只代表创建/启动请求
// 被接受，配置写错时容器会立刻退出，而 up 往往仍返回 0。
func (s *service) composeUp(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()

	args := []string{
		"compose",
		"--env-file", s.paths.envFile,
		"-f", s.paths.composeFile,
		"up", "-d", "--no-deps", "--force-recreate",
	}
	args = append(args, composeServices...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = s.paths.deployDir
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return text, hostError(fmt.Errorf("重建容器超时（%s）：%s", dockerTimeout, text))
		}
		return text, hostError(fmt.Errorf("重建容器失败: %v\n%s", err, text))
	}

	if err := s.verifyServicesRunning(ctx); err != nil {
		return text, err
	}
	return text, nil
}

const (
	// containerStableChecks 是「容器仍在运行」需要连续确认的次数。
	//
	// 只查一次是不够的：配置写错时容器会起来、加载失败、立刻退出，而
	// `compose ps` 恰好落在这一两秒里就会看到「在运行」。连续确认把观察
	// 窗口拉到 containerStableChecks*containerStableInterval（默认 2 秒），
	// 「启动即退出」基本都会被抓住。
	containerStableChecks = 3
	// containerStableInterval 是两次确认之间的间隔。
	containerStableInterval = time.Second
)

// verifyServicesRunning 确认 composeServices 都**持续**处于运行状态。
//
// 这是「Applied 是否可信」的最后一道检查：没有它，接口会把一次
// 「容器启动即崩溃」当成应用成功，管理员看到的界面与实际运行状态分叉。
func (s *service) verifyServicesRunning(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	streak := 0
	for {
		missing, err := s.notRunningServices(probeCtx)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			// 容器刚创建时可能短暂处于 created/starting，不能把一次
			// 尚未完成的启动直接当成配置失败。继续轮询，直到稳定窗口
			// 成功或总超时；最终错误会带出未运行的服务名。
			streak = 0
			select {
			case <-probeCtx.Done():
				return hostError(fmt.Errorf(
					"容器重建后在稳定检查窗口内仍未运行: %s（请查看 docker compose logs）",
					strings.Join(missing, ", ")))
			case <-time.After(containerStableInterval):
				continue
			}
		}
		streak++
		if streak >= containerStableChecks {
			return nil
		}
		select {
		case <-probeCtx.Done():
			return hostError(fmt.Errorf("重建后等待容器稳定超时: %w", probeCtx.Err()))
		case <-time.After(containerStableInterval):
		}
	}
}

// serviceStates 读取各 compose 容器的实际状态，用于「部分应用」时如实上报。
//
// 用 --format 取「服务名 | 状态」一行一条。使用竖线而不是 Tab：
// 不同 Compose 版本对转义序列的输出方式可能不同，固定分隔符能让解析
// 明确失败而不是把整行静默塞进 Name、留下空 State。老版本 compose 不认
// 这个参数时返回空列表——宁可少给信息，也不要掩盖真正的重建错误。
func (s *service) serviceStates(ctx context.Context) []tlscfg.ServiceState {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := runDockerIn(probeCtx, s.paths.deployDir, composePSArgs(s.paths)...)
	if err != nil {
		return nil
	}
	var states []tlscfg.ServiceState
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 || strings.TrimSpace(parts[0]) == "" {
			log.Printf("[lt-config] 无法解析 compose 状态行 %q", line)
			continue
		}
		state := strings.TrimSpace(parts[1])
		if health := strings.TrimSpace(parts[2]); health != "" {
			state += " / health=" + health
		}
		if exitCode := strings.TrimSpace(parts[3]); exitCode != "" {
			state += " / exit=" + exitCode
		}
		states = append(states, tlscfg.ServiceState{
			Name:  strings.TrimSpace(parts[0]),
			State: state,
		})
	}
	return states
}

// notRunningServices 返回当前不在运行状态的 composeServices。
func (s *service) notRunningServices(ctx context.Context) ([]string, error) {
	// 用 --all + 明确分隔符读取状态、健康度和退出码；只看 --services 会把
	// 「容器启动后立即退出」误认为服务存在并返回成功。
	out, err := runDockerIn(ctx, s.paths.deployDir, composePSArgs(s.paths)...)
	if err != nil {
		return nil, hostError(fmt.Errorf("重建后无法确认容器状态: %v\n%s", err, out))
	}
	running := make(map[string]bool, len(composeServices))
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, hostError(fmt.Errorf("无法解析 compose 容器状态行 %q", line))
		}
		name := strings.TrimSpace(parts[0])
		state := strings.ToLower(strings.TrimSpace(parts[1]))
		health := strings.ToLower(strings.TrimSpace(parts[2]))
		exitCode := strings.TrimSpace(parts[3])
		if state == "running" && (health == "" || health == "healthy") && exitCode == "0" {
			running[name] = true
		}
	}
	var missing []string
	for _, name := range composeServices {
		if !running[name] {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

// composePSArgs 组装 `docker compose ps` 的参数。
//
// serviceStates 与 notRunningServices 查的是同一件事，参数必须一模一样：
// 一处多给或少给一个 flag，两边的状态判断就会分叉——而它们一个用于「如实
// 上报」，一个用于「认定应用成功」，分叉的表现是界面说成功、实际没起来。
func composePSArgs(p paths) []string {
	return []string{
		"compose",
		"--env-file", p.envFile,
		"-f", p.composeFile,
		"ps", "-a", "--format", "{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}",
	}
}
