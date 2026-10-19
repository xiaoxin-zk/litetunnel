package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestComposeAfterDockerSkipsProbeWhenDaemonDown(t *testing.T) {
	var calls int32
	res := composeAfterDocker(
		dockerProbeResult{Found: true, Reason: "daemon 未启动"},
		func() composeProbeResult {
			atomic.AddInt32(&calls, 1)
			return composeProbeResult{Ready: true}
		})

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("daemon 不可用时不该探 compose，实际探了 %d 次", got)
	}
	if res.ComposeReady {
		t.Error("daemon 不可用时 ComposeReady 必须为假")
	}
	if res.ComposeReason != "" {
		t.Errorf("daemon 不可用时不该给 compose 的原因（会把管理员引去装插件），实际 %q", res.ComposeReason)
	}
	if res.Ready {
		t.Error("daemon 不可用时 Ready 必须保持假")
	}
}

func TestComposeAfterDockerReportsComposeSeparately(t *testing.T) {
	const composeReason = "docker compose 不可用（插件与独立 docker-compose 都没能跑起来）"
	res := composeAfterDocker(
		dockerProbeResult{Found: true, Ready: true},
		func() composeProbeResult { return composeProbeResult{Reason: composeReason} })

	if !res.Ready {
		t.Error("daemon 可用时 Ready 必须为真——compose 缺失不该改变 daemon 的结论")
	}
	if res.ComposeReady {
		t.Error("compose 探测失败时 ComposeReady 必须为假")
	}
	if res.ComposeReason != composeReason {
		t.Errorf("compose 的失败原因应当原样带出，实际 %q", res.ComposeReason)
	}

	ok := composeAfterDocker(
		dockerProbeResult{Found: true, Ready: true},
		func() composeProbeResult { return composeProbeResult{Ready: true} })
	if !ok.Ready || !ok.ComposeReady {
		t.Fatalf("daemon 与 compose 都可用时两个字段都应为真，实际 %+v", ok)
	}
	if ok.ComposeReason != "" {
		t.Errorf("compose 可用时不该留原因，实际 %q", ok.ComposeReason)
	}
}

func TestHealthReportsComposeReadySeparately(t *testing.T) {
	s, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{
			Found:         true,
			Ready:         true,
			ComposeReason: "docker compose 不可用：请安装 docker-compose-plugin",
		}
	})
	h := healthInto(t, s)
	if !h.Docker || !h.DockerReady {
		t.Fatalf("daemon 可用时 Docker/DockerReady 都应为真，实际 %+v", h)
	}
	if h.ComposeReady {
		t.Error("compose 不可用时 ComposeReady 必须为假")
	}
	if h.ComposeErr == "" {
		t.Error("compose 不可用时必须给出可读原因，否则界面只能给一句兜底")
	}
	if !strings.Contains(h.ComposeErr, "compose") {
		t.Errorf("原因应点明 compose，实际 %q", h.ComposeErr)
	}
	if !h.Available {
		t.Errorf("compose 缺失不该让 helper 自己报不可用（仅保存仍然可用），Reason=%q", h.Reason)
	}

	s2, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{Found: true, Reason: "daemon 未启动"}
	})
	h2 := healthInto(t, s2)
	if h2.DockerReady || h2.ComposeReady {
		t.Fatalf("daemon 不可用时两个 Ready 都应为假，实际 %+v", h2)
	}
	if h2.ComposeErr != "" {
		t.Errorf("daemon 不可用时不填 ComposeErr（那是连带结果），实际 %q", h2.ComposeErr)
	}

	s3, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{Found: true, Ready: true, ComposeReady: true}
	})
	h3 := healthInto(t, s3)
	if !h3.DockerReady || !h3.ComposeReady {
		t.Fatalf("一切正常时两个 Ready 都应为真，实际 %+v", h3)
	}
	if h3.DockerErr != "" || h3.ComposeErr != "" {
		t.Errorf("就绪时不该留任何错误文本，实际 docker=%q compose=%q", h3.DockerErr, h3.ComposeErr)
	}
}

func TestHealthComposeProbeIsCachedAndSingleFlight(t *testing.T) {
	var calls int32
	s, _ := newHealthService(t, func() dockerProbeResult {
		atomic.AddInt32(&calls, 1)
		return dockerProbeResult{Found: true, Ready: true, ComposeReady: true}
	})
	for i := 0; i < 5; i++ {
		if h := healthInto(t, s); !h.ComposeReady {
			t.Fatalf("第 %d 次请求应当报告 compose 可用", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("TTL 之内整份探测只应跑一次（含 compose 那一段），实际 %d 次", got)
	}

	var concurrent int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s2 := &service{}
	s2.dockerProbeFn = func() dockerProbeResult {
		atomic.AddInt32(&concurrent, 1)
		once.Do(func() {
			close(started)
			<-release
		})
		return dockerProbeResult{Found: true, Ready: true, ComposeReady: true}
	}

	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			defer wg.Done()
			if res := s2.dockerStatus(); !res.ComposeReady {
				t.Errorf("并发结论应当一致，实际 %+v", res)
			}
		}()
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("首轮探测始终没有开始")
	}
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&concurrent); got != 1 {
		t.Fatalf("并发请求只应触发一次探测，实际 %d 次", got)
	}
}

func TestProbeComposeHostIsSymmetric(t *testing.T) {
	res := probeComposeHost()
	if res.Ready {
		if res.Reason != "" {
			t.Errorf("就绪时不该同时给出失败原因，实际 %q", res.Reason)
		}
		return
	}
	if res.Reason == "" {
		t.Error("未就绪时必须给出可读原因，否则界面无从判断该装什么")
	}
	if !strings.Contains(res.Reason, "compose") {
		t.Errorf("原因应点明 compose，实际 %q", res.Reason)
	}
}

func TestTruncateRunesStillWorks(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := truncateRunes(long, 200)
	if r := []rune(got); len(r) != 201 {
		t.Errorf("应按字符截断到 200 + 省略号，实际 %d", len(r))
	}
}
