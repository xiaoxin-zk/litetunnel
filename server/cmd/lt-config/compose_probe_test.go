package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 这一组守的是缺陷 9：「daemon 能用」不等于「compose 能用」。
//
// 落点：本服务重建容器只用 `docker compose up`（见 compose.go），而早期
// 探测只跑 `docker info`。daemon 起来了、compose 插件没装（或只有 V1 的
// 独立二进制）时 docker info 照样成功，面板于是放行到「保存并应用」，
// 失败发生在文件已经写盘之后——配置与容器分处两个版本。
//
// 这里覆盖三件事：
//  1. 两个结论分别报告，原因不混在一起（daemon 坏 vs compose 坏）；
//  2. ComposeReady 恒蕴含 DockerReady，反之不成立；
//  3. 新增的 compose 探测没有破坏缓存与单飞（一次健康检查仍然只跑一轮）。

// TestComposeAfterDockerSkipsProbeWhenDaemonDown：daemon 不可用时**不允许**
// 再探 compose。
//
// 性质是「不调用」，所以只能靠一个会计数的 probeCompose 验证：多起一个进程
// 只为报一个连带为假的状态，既浪费又是健康检查被高频轮询时的进程浪费。
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

// TestComposeAfterDockerReportsComposeSeparately：daemon 可用、compose 不可用
// 时，必须能说清是「compose 的问题」而不是「Docker 的问题」。
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

	// 正向对照：两者都可用时都真，且不留旧错误。
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

// TestHealthReportsComposeReadySeparately 覆盖 Health 字段的契约（前端按它
// 决定按钮能否点）。
func TestHealthReportsComposeReadySeparately(t *testing.T) {
	// 场景 A：daemon 可用、compose 缺失。应用类按钮必须被禁用，但「仅保存」
	// 仍然可用——所以 Available 不能被压成 false。
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

	// 场景 B：daemon 不可用。compose 结论是连带为假，ComposeErr 必须留空，
	// 否则界面会把「去启动 docker」写成「去装 compose 插件」。
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

	// 场景 C：一切正常。两个 Ready 都为真，两个 Err 都留空。
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

// TestHealthComposeProbeIsCachedAndSingleFlight：新增的 compose 探测不能破坏
// 「TTL 内只探一次、并发只探一次」。
//
// 关键点：缓存的是**整份**结论（daemon + compose 在同一次探测里跑完），所以
// 断言仍然只数一次调用。
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

	// 并发：仍然只允许一次。
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

// TestProbeComposeHostIsSymmetric 覆盖真实 compose 探测的两个分支（不依赖本机
// 是否装了 compose）：要么就绪，要么给出一条可读原因。
//
// 与 docker 那个用例同样的对称写法：ubuntu-latest 上装了 docker 但未必装了
// compose 插件，本机（Windows）也可能没有，硬性要求某一种只会得到一条
// 与环境相关的失败。
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

// TestTruncateRunesStillWorks 保持对新增调用点的约束：compose 的报错同样要
// 截断，不能整段灌进健康检查响应。
func TestTruncateRunesStillWorks(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := truncateRunes(long, 200)
	if r := []rune(got); len(r) != 201 {
		t.Errorf("应按字符截断到 200 + 省略号，实际 %d", len(r))
	}
}
