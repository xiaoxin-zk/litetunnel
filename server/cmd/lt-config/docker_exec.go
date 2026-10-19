package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// 本文件是「怎么调 docker，以及调不动时算哪一类错误」的独立单元。
//
// # 为什么单独拆出来
//
// 这是全服务**唯一**会起 docker 子进程的地方（另一处是 dockerprobe.go 的
// 可用性探测，它只读版本信息、不改变任何状态）。把它与「用 compose 干什么」
// 分开，是为了让「本服务到底能动宿主机的什么」一目了然：这里只有执行与
// 归类，重建什么、校验什么在 compose.go / validate.go。
//
// # 错误分类为什么重要
//
// docker 的失败有两类，处置方式相反：
//
//   - 宿主机动不了手（命令不存在、daemon 连不上、调用超时/被取消）→ 502，
//     要去查宿主机的 docker 服务；
//   - 命令执行了但没通过（Caddy 拒绝了这份配置）→ 422，管理员原地改配置。
//
// 混在一起的后果是把运维问题指向用户：用户会一直怀疑自己的 Caddyfile，
// 而实际上 daemon 根本没起来。

// runDocker 在当前目录执行 docker 命令。
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
