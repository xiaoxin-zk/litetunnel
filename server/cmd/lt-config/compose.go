package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
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
func (s *service) composeUp(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()

	args := []string{
		"compose",
		"--env-file", s.paths.envFile,
		"-f", s.paths.composeFile,
		"up", "-d", "--no-deps",
	}
	args = append(args, composeServices...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = s.paths.deployDir
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return text, fmt.Errorf("重建容器超时（%s）：%s", dockerTimeout, text)
		}
		return text, fmt.Errorf("重建容器失败: %v\n%s", err, text)
	}
	return text, nil
}

func runDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return text, fmt.Errorf("docker 调用超时")
		}
		return text, err
	}
	return text, nil
}
