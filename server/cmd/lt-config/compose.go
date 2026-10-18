package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件是**唯一**执行 docker 命令的地方。
//
// 单独成文件是为了让「本服务到底能动宿主机的什么」一目了然：
// 只有这里能起容器，而它只认一个 compose 文件与两个写死的服务名。

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
			return hostError(fmt.Errorf(
				"容器重建后未保持运行: %s（多半是新配置未被接受，请查看 docker compose logs）",
				strings.Join(missing, ", ")))
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
// 用 --format 取「服务名 + 状态」一行一条。老版本 compose 不认这个参数，
// 那就返回空列表——宁可少给信息，也不要在这里再报一个错误掩盖真正的问题
// （容器重建已经失败了，管理员需要的是原始错误）。
func (s *service) serviceStates(ctx context.Context) []tlscfg.ServiceState {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := runDockerIn(probeCtx, s.paths.deployDir,
		"compose",
		"--env-file", s.paths.envFile,
		"-f", s.paths.composeFile,
		"ps", "-a", "--format", "{{.Service}}\t{{.State}}")
	if err != nil {
		return nil
	}
	var states []tlscfg.ServiceState
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, state, ok := strings.Cut(line, "\t")
		if !ok {
			name, state = line, ""
		}
		states = append(states, tlscfg.ServiceState{
			Name:  strings.TrimSpace(name),
			State: strings.TrimSpace(state),
		})
	}
	return states
}

// notRunningServices 返回当前不在运行状态的 composeServices。
func (s *service) notRunningServices(ctx context.Context) ([]string, error) {
	// compose ps 默认只列运行中的容器（--all 才包含已退出的），
	// 所以不需要额外参数，老版本 compose 也能用。
	out, err := runDockerIn(ctx, s.paths.deployDir,
		"compose",
		"--env-file", s.paths.envFile,
		"-f", s.paths.composeFile,
		"ps", "--services")
	if err != nil {
		return nil, hostError(fmt.Errorf("重建后无法确认容器状态: %v\n%s", err, out))
	}
	running := make(map[string]bool, len(composeServices))
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
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

func runDocker(ctx context.Context, args ...string) (string, error) {
	return runDockerIn(ctx, "", args...)
}

// runDockerIn 在指定目录执行 docker 命令；dir 为空时沿用当前目录。
func runDockerIn(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			// 保留 context 错误，让调用方能用 errors.Is 判断超时/取消——
			// 这两者都意味着「宿主机动不了」，该按 502 处理。
			return text, fmt.Errorf("docker 调用中断: %w", ctx.Err())
		}
		// daemon 不可用 / socket 权限不足同样是 ExitError：在这里就把它
		// 标出来，调用方不必再去猜输出文本里哪一段才是原因。
		if looksLikeDockerHostFailure(text) {
			return text, fmt.Errorf("%w: %v", errDockerHost, err)
		}
		return text, err
	}
	return text, nil
}

// errDockerHost 表示 docker 命令确实执行了，但宿主机侧不可用：daemon 没起来、
// socket 权限不足、命名管道不存在、compose 插件缺失。
//
// 这类失败必须与「配置写错了」分开：它们不是用户能靠改配置文件解决的，
// 报 422 会把运维问题指向错误的方向（用户会一直怀疑自己的 Caddyfile）。
var errDockerHost = errors.New("docker 宿主机不可用")

// dockerHostFailureHints 是 docker CLI 在这些情形下的固定说法（小写匹配）。
//
// docker daemon 不可用、权限拒绝、socket 断开都表现为 ExitCode != 0，
// 而不是启动失败（*exec.Error）——只按错误类型判断时，它们会被归成
// 「命令执行了但没通过」，于是统统变成 422 配置错误。
var dockerHostFailureHints = []string{
	"cannot connect to the docker daemon",
	"is the docker daemon running",
	"error during connect",
	"permission denied while trying to connect to the docker daemon",
	"connect: permission denied",
	"docker.sock",
	"is not a docker command",
	"docker: not found",
	"the system cannot find the file specified",
}

// looksLikeDockerHostFailure 判断 docker 的输出是否指向宿主机侧故障。
func looksLikeDockerHostFailure(output string) bool {
	lower := strings.ToLower(output)
	for _, hint := range dockerHostFailureHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// isHostDockerError 判断一次 docker 调用失败是「宿主机动不了」（docker 命令
// 不存在/不可执行、daemon 连不上、调用超时或被取消），还是「命令执行了但
// 没通过」（例如 caddy 拒绝了这份配置）。前者按 502 处理，后者是配置问题
// 按 422 处理。
func isHostDockerError(err error) bool {
	if err == nil {
		return false
	}
	var ee *exec.Error
	if errors.As(err, &ee) {
		// 命令都没能启动：docker 二进制不存在或不可执行。
		return true
	}
	if errors.Is(err, errDockerHost) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
