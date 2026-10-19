package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func runDocker(ctx context.Context, args ...string) (string, error) {
	return runDockerIn(ctx, "", args...)
}

func runDockerIn(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return text, fmt.Errorf("docker 调用中断: %w", ctx.Err())
		}
		if looksLikeDockerHostFailure(text) {
			return text, fmt.Errorf("%w: %v", errDockerHost, err)
		}
		return text, err
	}
	return text, nil
}

var errDockerHost = errors.New("docker 宿主机不可用")

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

func looksLikeDockerHostFailure(output string) bool {
	lower := strings.ToLower(output)
	for _, hint := range dockerHostFailureHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func isHostDockerError(err error) bool {
	if err == nil {
		return false
	}
	var ee *exec.Error
	if errors.As(err, &ee) {
		return true
	}
	if errors.Is(err, errDockerHost) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
