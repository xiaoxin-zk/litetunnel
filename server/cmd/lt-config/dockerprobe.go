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

const dockerProbeTimeout = 2 * time.Second

const composeProbeTimeout = 1500 * time.Millisecond

const dockerProbeTTL = 12 * time.Second

type dockerProbeResult struct {
	Found         bool
	Ready         bool
	Reason        string
	ComposeReady  bool
	ComposeReason string
}

type composeProbeResult struct {
	Ready  bool
	Reason string
}

type dockerProbeCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	valid     bool
	result    dockerProbeResult
}

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

func (s *service) probeDocker() dockerProbeResult {
	if s.dockerProbeFn != nil {
		return s.dockerProbeFn()
	}
	return composeAfterDocker(probeDockerHost(), s.probeCompose)
}

func composeAfterDocker(res dockerProbeResult, probeCompose func() composeProbeResult) dockerProbeResult {
	if !res.Ready {
		return res
	}
	cres := probeCompose()
	res.ComposeReady = cres.Ready
	res.ComposeReason = cres.Reason
	return res
}

func (s *service) probeCompose() composeProbeResult {
	if s.composeProbeFn != nil {
		return s.composeProbeFn()
	}
	return probeComposeHost()
}

func probeDockerHost() dockerProbeResult {
	if _, err := exec.LookPath("docker"); err != nil {
		return dockerProbeResult{Reason: "未找到 docker 命令：校验与重建容器都依赖它"}
	}
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
	return dockerProbeResult{Found: true, Reason: "docker 命令存在，但宿主机不可用（daemon 未启动或无 socket 权限）：" +
		truncateRunes(text, 200)}
}

func probeComposeHost() composeProbeResult {
	pluginOut, pluginErr := runVersionProbe("docker", "compose", "version")
	if pluginErr == nil {
		return composeProbeResult{Ready: true}
	}

	detail := pluginOut
	if detail == "" {
		detail = pluginErr.Error()
	}
	return composeProbeResult{Reason: "docker compose V2 不可用：校验与重建容器统一使用 docker compose，请安装 docker-compose-plugin；" +
		"docker compose version 的输出：" + truncateRunes(detail, 200)}
}

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

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
