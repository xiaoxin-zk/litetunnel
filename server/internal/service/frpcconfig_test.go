package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestBuildFrpcConfigLogsToConsole 覆盖「frpc 日志写进文件，客户端什么都看不到」。
//
// 客户端靠解析 frpc 的输出判断这条隧道到底起来没有：
//
//   - `start proxy success` → 界面上补一句「隧道启动成功」+ 可用地址；
//   - 错误行 → 显示「为什么一直连不上」。
//
// 而配置里 log.to 若是文件路径，frpc 的 stdout 永远是空的，上面两条提示
// **永远不会出现**：用户只看到「已启动 frpc（PID …）」之后就再无下文，
// 分不清是在连、还是已经连上了。
func TestBuildFrpcConfigLogsToConsole(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "cfguser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(&tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	cfg, err := svc.BuildFrpcConfig(u, []model.Tunnel{tun})
	if err != nil {
		t.Fatalf("生成配置失败: %v", err)
	}

	if !strings.Contains(cfg, `log.to = "console"`) {
		t.Errorf("日志必须输出到 console，否则客户端读不到 frpc 的输出（无法判断上线/报错）:\n%s", cfg)
	}
	if strings.Contains(cfg, "./frpc.log") {
		t.Errorf("不该再把日志写进文件（客户端会因此看不到任何 frpc 输出）:\n%s", cfg)
	}
}

// TestAllocatePortIsRandom 覆盖「端口按固定顺序分配、外部可预测」。
//
// 从前的起点由用户 ID 派生、然后顺序向后扫：同一用户每次都拿到池里靠前的
// 第一个空位，连续建几条隧道就能把用到的整段端口推出来。端口对外就是服务
// 入口，可预测会明显降低扫描/撞库的成本。
//
// 这里不检查分布是否均匀（那是统计问题），只钉住「不是每次都给同一个」——
// 旧实现下这一条必然失败（空池里恒返回同一个端口）。
func TestAllocatePortIsRandom(t *testing.T) {
	const (
		portStart = 30000
		portEnd   = 31999
	)
	svc := newTestServices(t, &config.Config{PortRangeStart: portStart, PortRangeEnd: portEnd})

	seen := map[int]struct{}{}
	const draws = 30
	for i := 0; i < draws; i++ {
		p, err := svc.allocatePort(svc.DB, 1)
		if err != nil {
			t.Fatalf("第 %d 次分配失败: %v", i+1, err)
		}
		if p < portStart || p > portEnd {
			t.Fatalf("分配出的端口越界: %d", p)
		}
		seen[p] = struct{}{}
	}

	if len(seen) < 2 {
		t.Fatalf("端口分配必须随机（否则外部可预测）：%d 次全部落在同一个端口", draws)
	}
}

// TestIsPortConflict 覆盖「端口撞车后不重试」的判定依据。
//
// 两个驱动的报错文本不同，而重试与否全看这个判定：漏判会让一次本来重试就能
// 成功的创建直接失败（用户看到「创建失败」）；误判则会把真正的错误也重试
// 几遍（无害，最终仍返回原始错误）。
func TestIsPortConflict(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("UNIQUE constraint failed: lt_tunnels.remote_port"), true},
		{errors.New("ERROR: duplicate key value violates unique constraint \"idx_tunnels_remote_port\""), true},
		{errors.New("connection refused"), false},
		{errors.New("context deadline exceeded"), false},
	}
	for _, tc := range cases {
		if got := isPortConflict(tc.err); got != tc.want {
			t.Errorf("isPortConflict(%v) = %v，期望 %v", tc.err, got, tc.want)
		}
	}
}

// TestAllocatePortSkipsUsed 覆盖反面：随机起点不能把已占用的端口再分出去。
func TestAllocatePortSkipsUsed(t *testing.T) {
	const (
		portStart = 30000
		portEnd   = 30004
	)
	svc := newTestServices(t, &config.Config{PortRangeStart: portStart, PortRangeEnd: portEnd})

	u := &model.User{Username: "portused", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// 占掉池里的前四个端口，只剩一个可用。
	used := map[int]struct{}{}
	for _, p := range []int{portStart, portStart + 1, portStart + 2, portStart + 3} {
		tun := model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("t%d", p),
			Type: model.ProxyTypeTCP, LocalIP: "127.0.0.1", LocalPort: 25565,
			RemotePort: p, Status: model.TunnelStatusActive,
		}
		if err := svc.DB.Create(&tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
		used[p] = struct{}{}
	}

	for i := 0; i < 10; i++ {
		p, err := svc.allocatePort(svc.DB, 1)
		if err != nil {
			t.Fatalf("应还能分到最后一个空闲端口: %v", err)
		}
		if _, ok := used[p]; ok {
			t.Fatalf("分配到了已占用的端口 %d", p)
		}
		if p != portEnd {
			t.Fatalf("池里只剩 %d 可用，实际分到 %d", portEnd, p)
		}
	}
}
