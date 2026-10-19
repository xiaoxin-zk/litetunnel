package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type queryCounter struct {
	logger.Interface
	n *atomic.Int32
}

func (q queryCounter) Trace(_ context.Context, _ time.Time, _ func() (string, int64), _ error) {
	q.n.Add(1)
}

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

func TestFrpcConfigRevTracksEveryInput(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "revuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	base := model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}

	revOf := func(tun model.Tunnel) string {
		t.Helper()
		info, err := svc.BuildClientInfo(u)
		if err != nil {
			t.Fatalf("组装接入信息失败: %v", err)
		}
		return FrpcConfigRev(svc.FrpcConfigHeader(info) + svc.FrpcConfigProxy(u, tun, svc.EffectiveBandwidth(u)))
	}

	origin := revOf(base)

	full, err := svc.BuildFrpcConfig(u, []model.Tunnel{base})
	if err != nil {
		t.Fatalf("生成配置失败: %v", err)
	}
	if !strings.Contains(full, svc.FrpcConfigProxy(u, base, svc.EffectiveBandwidth(u))) {
		t.Fatal("单条隧道的渲染结果必须与完整配置里的那一段逐字节相同")
	}

	changes := map[string]func(t *model.Tunnel){
		"停用":    func(t *model.Tunnel) { t.Status = model.TunnelStatusDisabled },
		"改名":    func(t *model.Tunnel) { t.Name = "mc2" },
		"改本地端口": func(t *model.Tunnel) { t.LocalPort = 25566 },
		"改本地地址": func(t *model.Tunnel) { t.LocalIP = "10.0.0.2" },
		"改远程端口": func(t *model.Tunnel) { t.RemotePort = 20002 },
		"开加密":   func(t *model.Tunnel) { t.UseEncryption = true },
		"开压缩":   func(t *model.Tunnel) { t.UseCompression = true },
		"改协议":   func(t *model.Tunnel) { t.Type = model.ProxyTypeUDP },
	}
	for name, mutate := range changes {
		tun := base
		mutate(&tun)
		if got := revOf(tun); got == origin {
			t.Errorf("%s 之后摘要没变:客户端会跳过拉取,一直跑旧配置", name)
		}
	}

	httpBase := base
	httpBase.Type = model.ProxyTypeHTTP
	httpBase.RemotePort = 0
	httpBase.Domain = "a.example.com"
	httpOrigin := revOf(httpBase)

	httpChanged := map[string]func(t *model.Tunnel){
		"改域名":    func(t *model.Tunnel) { t.Domain = "b.example.com" },
		"域名换子域名": func(t *model.Tunnel) { t.Domain, t.Subdomain = "", "sub" },
	}
	for name, mutate := range httpChanged {
		tun := httpBase
		mutate(&tun)
		if got := revOf(tun); got == httpOrigin {
			t.Errorf("HTTP 隧道%s之后摘要没变:客户端会跳过拉取,一直跑旧配置", name)
		}
	}

	if again := revOf(base); again != origin {
		t.Fatalf("同一个输入算出的摘要必须稳定:第一次 %s,第二次 %s", origin, again)
	}
}

func TestEnsureClientSecretConcurrent(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "secretrace", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	const n = 8
	results := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			local := *u
			s, err := svc.EnsureClientSecret(&local)
			if err != nil {
				results[i] = "ERR: " + err.Error()
				return
			}
			results[i] = s
		}(i)
	}
	wg.Wait()

	var db model.User
	if err := svc.DB.First(&db, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.ClientSecret == "" {
		t.Fatal("并发首次接入后库里必须有凭据")
	}
	for i, got := range results {
		if got != db.ClientSecret {
			t.Fatalf("第 %d 个并发请求拿到 %q，库里生效的是 %q：拿到的密钥会立刻失效",
				i, got, db.ClientSecret)
		}
	}
}

func TestFrpcConfigProxyDoesNotQueryDB(t *testing.T) {
	svc := newTestServices(t, nil)

	past := time.Now().Add(-time.Hour)
	u := &model.User{
		Username:      "expiredbw",
		Password:      "not-used",
		Status:        model.UserStatusActive,
		GroupExpireAt: &past,
	}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}

	var queries atomic.Int32
	svc.DB = svc.DB.Session(&gorm.Session{Logger: queryCounter{Interface: logger.Discard, n: &queries}})

	limit := svc.EffectiveBandwidth(u)
	queries.Store(0)

	for i := 0; i < 5; i++ {
		if got := svc.FrpcConfigProxy(u, tun, limit); !strings.Contains(got, "[[proxies]]") {
			t.Fatalf("第 %d 次渲染结果异常: %q", i+1, got)
		}
	}
	if n := queries.Load(); n != 0 {
		t.Fatalf("渲染单条隧道不该查库（N+1）：5 次渲染共查了 %d 次", n)
	}
}

func TestQueryInBatchesCoversAllIDs(t *testing.T) {
	svc := newTestServices(t, nil)

	const n = 7
	ids := make([]uint, 0, n)
	for i := 0; i < n; i++ {
		u := &model.User{
			Username: fmt.Sprintf("batch%d", i),
			Password: "not-used",
			Status:   model.UserStatusActive,
		}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
		ids = append(ids, u.ID)
	}

	old := inQueryBatch
	inQueryBatch = 2
	t.Cleanup(func() { inQueryBatch = old })

	users, err := queryInBatches[model.User](svc.DB, "id", ids)
	if err != nil {
		t.Fatalf("分批查询失败: %v", err)
	}
	if len(users) != n {
		t.Fatalf("分批查询必须覆盖全部 id：期望 %d 条，实际 %d 条", n, len(users))
	}
	seen := make(map[uint]bool, n)
	for i := range users {
		if seen[users[i].ID] {
			t.Fatalf("id %d 被重复返回（批次边界算错了）", users[i].ID)
		}
		seen[users[i].ID] = true
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatalf("id %d 没有被查到（批次漏了尾部）", id)
		}
	}

	if got, err := queryInBatches[model.Tunnel](svc.DB, "user_id", nil); err != nil || len(got) != 0 {
		t.Fatalf("空 id 集合应返回空结果，实际 %d 条 / %v", len(got), err)
	}
}

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
