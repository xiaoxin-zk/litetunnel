package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

const dockerTimeout = 3 * time.Minute

var composeServices = []string{"caddy", "frps"}

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
	containerStableChecks   = 3
	containerStableInterval = time.Second
)

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

func (s *service) serviceStates(ctx context.Context) ([]tlscfg.ServiceState, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := runDockerIn(probeCtx, s.paths.deployDir, composePSArgs(s.paths)...)
	if err != nil {
		return nil, fmt.Errorf("读取 compose 服务状态失败: %w", err)
	}
	var states []tlscfg.ServiceState
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("无法解析 compose 状态行 %q", line)
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
	return states, nil
}

func (s *service) notRunningServices(ctx context.Context) ([]string, error) {
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

func composePSArgs(p paths) []string {
	return []string{
		"compose",
		"--env-file", p.envFile,
		"-f", p.composeFile,
		"ps", "-a", "--format", "{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}",
	}
}
