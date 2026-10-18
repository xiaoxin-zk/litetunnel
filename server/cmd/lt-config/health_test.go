package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 这一组守的是 /health 对 docker 的两层报告，以及它的缓存/单飞行为。
//
// 背景：过去只做 exec.LookPath("docker")，那只证明「命令在 PATH 里」。
// docker 装了但 daemon 没起来、或本服务没有 socket 权限时，LookPath 照样
// 成功，面板一路放行到「保存」才在重建容器那步失败——而那时文件已经写盘了。
//
// 另外 /health 会被部署脚本高频轮询：每次请求都起一个 docker 进程是不可接受
// 的，所以必须带 TTL 缓存，并且并发请求只允许一次真实探测。

// newHealthService 造一个 /health 能跑起来的 service，docker 探测用替身。
//
// 所有 handleHealth 会检查的文件都写进临时目录：否则「缺少文件」会先把
// Available 压成 false，用例就分不清失败原因是 docker 还是缺文件。
// 探测替身让测试完全不依赖本机有没有 docker、daemon 是否在跑。
func newHealthService(t *testing.T, probe func() dockerProbeResult) (*service, paths) {
	t.Helper()
	s, p := newRenderOnlyService(t)

	p.composeFile = filepath.Join(p.deployDir, "docker-compose.yml")
	if err := os.WriteFile(p.composeFile, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("写入 compose 文件失败: %v", err)
	}
	s.paths = p
	s.dockerProbeFn = probe
	return s, p
}

// healthInto 发一次 GET /health 并把响应解出来。
func healthInto(t *testing.T, s *service) tlscfg.Health {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("健康检查必须返回 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var h tlscfg.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatalf("解析健康检查响应失败: %v", err)
	}
	return h
}

// TestHealthSeparatesCommandFromHostReadiness 覆盖问题 10 的判定：
// 命令在但 daemon 不通时，Docker=true、DockerReady=false，且给出中文原因；
// 这条结论不得影响 HTTP 200，也不得把 Available 压成 false（helper 本身
// 仍能读配置、渲染并给出校验结论）。
func TestHealthSeparatesCommandFromHostReadiness(t *testing.T) {
	const hostReason = "docker 命令存在，但宿主机不可用（daemon 未启动、无 socket 权限或 compose 插件缺失）：" +
		"Cannot connect to the Docker daemon"
	s, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{Found: true, Reason: hostReason}
	})

	h := healthInto(t, s)
	if !h.Docker {
		t.Error("命令存在时 Docker 应为 true")
	}
	if h.DockerReady {
		t.Error("daemon 不可达时 DockerReady 必须为 false")
	}
	if h.DockerErr == "" {
		t.Error("DockerReady 为假时必须给出可读原因")
	}
	if !strings.Contains(h.DockerErr, "宿主机不可用") {
		t.Errorf("原因应说明是宿主机侧的问题，实际 %q", h.DockerErr)
	}
	if !h.Available {
		t.Errorf("docker 不可用不该让 helper 自己报不可用（它仍能读配置并渲染），Reason=%q", h.Reason)
	}

	// 命令本身都不在时才把 Available 压成 false：那时校验与重建都无从谈起。
	s2, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{Reason: "未找到 docker 命令：校验与重建容器都依赖它"}
	})
	h2 := healthInto(t, s2)
	if h2.Docker {
		t.Error("命令不存在时 Docker 应为 false")
	}
	if h2.DockerReady {
		t.Error("命令不存在时 DockerReady 必须为 false")
	}
	if h2.Available {
		t.Error("docker 命令缺失时必须报告 helper 不可用")
	}
	if h2.Reason == "" {
		t.Error("不可用时必须给出原因")
	}
	if h2.DockerErr == "" {
		t.Error("docker 不可用时也应填 DockerErr，便于界面直接展示")
	}
}

// TestHealthReportsDockerReadyWhenHostUsable 是上面的正向对照：
// daemon 可用时两个字段都为真，且 DockerErr 必须留空（避免界面显示一条
// 吓人的旧错误）。
func TestHealthReportsDockerReadyWhenHostUsable(t *testing.T) {
	s, _ := newHealthService(t, func() dockerProbeResult {
		return dockerProbeResult{Found: true, Ready: true}
	})

	h := healthInto(t, s)
	if !h.Docker || !h.DockerReady {
		t.Fatalf("宿主机可用时 Docker/DockerReady 都应为 true，实际 %+v", h)
	}
	if h.DockerErr != "" {
		t.Errorf("可用时不该有 DockerErr，实际 %q", h.DockerErr)
	}
	if !h.Available {
		t.Errorf("一切正常时 Available 应为 true，Reason=%q", h.Reason)
	}
}

// TestHealthCachesDockerProbeWithinTTL 守住缓存：TTL 之内多次请求只允许一次
// 真实探测。没有缓存时，部署脚本每次轮询都会在宿主机上起一个 docker 进程。
func TestHealthCachesDockerProbeWithinTTL(t *testing.T) {
	var calls int32
	s, _ := newHealthService(t, func() dockerProbeResult {
		atomic.AddInt32(&calls, 1)
		return dockerProbeResult{Found: true, Ready: true}
	})

	for i := 0; i < 5; i++ {
		h := healthInto(t, s)
		if !h.DockerReady {
			t.Fatalf("第 %d 次请求应当报告 docker 可用", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("TTL 之内只应探测一次，实际 %d 次", got)
	}
}

// TestDockerStatusSingleFlight 并发请求只允许一次真实探测。
//
// 用「首个探测卡在 channel 上、其余 goroutine 在此刻并发进入」制造真实重叠：
// 如果 dockerStatus 没有用互斥锁把并发请求串起来，会有多个探测同时跑。
func TestDockerStatusSingleFlight(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	probe := func() dockerProbeResult {
		atomic.AddInt32(&calls, 1)
		// 第一个探测先报到、再卡住：主 goroutine 等 started 之后才放行，
		// 其余请求在这段窗口里并发进入，重叠是构造出来的而不是碰运气。
		once.Do(func() {
			close(started)
			<-release
		})
		return dockerProbeResult{Found: true, Ready: true}
	}

	s := &service{dockerProbeFn: probe}

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if res := s.dockerStatus(); !res.Ready {
				t.Errorf("并发探测的结论应当一致，实际 %+v", res)
			}
		}()
	}

	// 等第一个探测确实开始，再放行。这里带超时而不是裸等：如果哪天
	// dockerStatus 根本不调用探测，裸等会把整轮测试挂到 go test 的超时上限，
	// 只留下一个「超时」而看不出是哪条断言坏掉了。
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("首轮探测始终没有开始：dockerStatus 没有调用探测")
	}
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("并发请求只应触发一次探测，实际 %d 次", got)
	}
}

// TestProbeDockerHostAlwaysExplainsFailure 覆盖真实探测的两个分支（不依赖
// 本机状态）：要么就绪，要么给出一条可读原因，不允许「既没就绪也没有原因」。
// 本机若没有 docker，还要求原因里点明 docker。
//
// 这里不假设 CI 上有 docker（ubuntu-latest 通常有客户端但未必有 daemon），
// 所以断言写成对称的两种情形，而不是硬性要求某一种。
func TestProbeDockerHostAlwaysExplainsFailure(t *testing.T) {
	res := probeDockerHost()
	if res.Ready {
		if !res.Found {
			t.Error("Ready 为真时 Found 必须为真")
		}
		if res.Reason != "" {
			t.Errorf("就绪时不该同时给出失败原因，实际 %q", res.Reason)
		}
		return
	}
	if res.Reason == "" {
		t.Error("未就绪时必须给出可读原因，否则界面无从判断该修什么")
	}
	if !res.Found && !strings.Contains(res.Reason, "docker") {
		t.Errorf("命令缺失的原因应点明 docker，实际 %q", res.Reason)
	}
}

// TestTruncateRunes 守住「docker 报错不整段灌进健康检查」。
func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("短", 10); got != "短" {
		t.Errorf("未超长时不该改动，实际 %q", got)
	}
	got := truncateRunes("这是一段很长的中文输出", 5)
	if r := []rune(got); len(r) != 6 || r[len(r)-1] != '…' {
		t.Errorf("应按字符截断并加省略号，实际 %q", got)
	}
}
