package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestTrafficBaselineSurvivesRestart 覆盖「控制面重启后重复计入当天流量」。
//
// 采样基线原先只在内存里。只重启控制面（frps 没重启、当天累计值还在）时，
// 第一次采集会把当天全部流量当成新增量记一遍——用户配额被凭空扣掉一大截，
// 统计也翻倍。滚动升级恰好就是这个形态。
func TestTrafficBaselineSurvivesRestart(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "restarttraffic", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20071,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()

	// frps 今天已经累计了 5000 字节（在我们启动之前它就在跑了）。
	frps.total.Store(5000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5000 {
		t.Fatalf("首轮应记 5000，实际 %d", got)
	}

	// 模拟「只重启控制面、frps 没重启」：同一个库上新建一套 Services。
	//
	// 旧进程若是崩溃退出（没走优雅关停），采集租约还挂在它名下；
	// 这里把租约置为已过期，模拟租期到了之后新实例接手。
	restarted := New(svc.DB, cfg)
	restarted.Frps = NewFrpsClient(cfg)
	restarted.loadTrafficBaseline()
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatalf("释放采集租约失败: %v", err)
	}

	// frps 的当天累计值没变，重启后的这一轮不该再记一遍。
	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5000 {
		t.Fatalf("重启后不该重复计入当天已有流量，实际 %d，期望 5000", got)
	}

	// 之后新增的流量仍要正常记上（基线恢复不能把采集算坏）。
	frps.total.Store(5200)
	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5200 {
		t.Fatalf("重启后新增流量应正常记入，实际 %d，期望 5200", got)
	}
}

// TestTrafficCollectorRestoresBaselineOnStart 覆盖上面那条修复的**接线**：
// 采集器必须在第一次采集之前恢复基线，否则修复形同没做。
func TestTrafficCollectorRestoresBaselineOnStart(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	if err := svc.DB.Create(&model.TrafficBaseline{
		ProxyName: "lt_u1.mc", Date: time.Now().Format("2006-01-02"),
		InBytes: 123, OutBytes: 456,
	}).Error; err != nil {
		t.Fatalf("写入基线失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartTrafficCollector(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		svc.Runtime.mu.RLock()
		cur, ok := svc.Runtime.lastStat["lt_u1.mc"]
		svc.Runtime.mu.RUnlock()
		if ok {
			if cur.in != 123 || cur.out != 456 {
				t.Fatalf("恢复的基线不对: %+v", cur)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("采集器启动时应先恢复采样基线，否则重启后会重复计入当天流量")
}

// TestTrafficCollectorSeedsBaselineAfterMigration 覆盖「基线首次迁移不重复计入」。
//
// TrafficBaseline 表是后续版本加入的：升级旧库时它不存在/为空，而 frps 的
// 当天累计值是旧版本**已经计过**的。此时第一轮采集若照常从零算增量，
// 用户会被重复扣费、甚至触发超额封禁。
//
// 迁移标记（KeyTrafficBaselineReady）缺失时，第一轮只写基线、不计增量；
// 标记落定后恢复正常。表读不出来（升级中途）时整轮跳过，等下个周期重试。
func TestTrafficCollectorSeedsBaselineAfterMigration(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	u := &model.User{Username: "skipcollect", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20091,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	// frps 今天已经累计了 5000 字节——这些是旧版本已经计入过的。
	frps.total.Store(5000)

	// 模拟升级前状态：基线表不存在，迁移标记（settings 表）也缺失。
	if err := svc.DB.Migrator().DropTable(&model.TrafficBaseline{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartTrafficCollector(ctx)

	// 给它足够时间跑第一次（被跳过的）采集。
	//
	// 观测点用「在线状态」而不是「已用流量」：这一轮里落库本身也会失败
	// （基线表刚被删掉），所以只看流量的话区分不出「跳过」与「失败」。
	// 在线状态是在落库**之前**更新的，能干净地区分两者。
	time.Sleep(700 * time.Millisecond)
	if svc.Runtime.IsTunnelOnline(tun.ID) {
		t.Fatal("基线不可用时不该采集（会把当天累计值整个记成新增量），本轮连在线状态都不该更新")
	}
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 0 {
		t.Fatalf("基线不可用时不该记入流量，实际已记 %d", got)
	}

	// 重建表：迁移标记仍然缺失 → 第一轮是「播种轮」。
	if err := svc.DB.AutoMigrate(&model.TrafficBaseline{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if svc.Settings.Bool(KeyTrafficBaselineReady) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !svc.Settings.Bool(KeyTrafficBaselineReady) {
		t.Fatal("播种轮完成后应落下迁移标记")
	}
	// 采集确实跑了（在线状态在落库前更新），但当天累计值没有被重复计入。
	if !svc.Runtime.IsTunnelOnline(tun.ID) {
		t.Fatal("播种轮应正常采集在线状态")
	}
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 0 {
		t.Fatalf("首次迁移的第一轮只应写基线、不计增量，实际已记 %d（这正是要防的重复计入）", got)
	}

	// 标记落定后恢复正常：frps 计数从 5000 涨到 6500，下一轮只记增量 1500。
	frps.total.Store(6500)
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if got := tunnelTrafficUsed(t, svc, tun.ID); got == 1500 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("标记落定后应按增量计流量，实际已记 %d，期望 1500", tunnelTrafficUsed(t, svc, tun.ID))
}

// TestCollectTrafficKeepsBaselineForAbsentProxy 覆盖「代理短暂缺席后被重复计费」。
//
// 基线（Runtime.lastStat）原先每轮按**本轮看到的代理**整体替换，没出现的直接
// 丢弃。可代理缺席一轮是常见事：客户端重连、frps 分页期间一删一增的错位都会
// 造成它。它重新出现时基线已经没了，于是「当前值 - 0」= frps 的当天累计值被
// 整个再记一遍——用户凭空多扣一大截流量，日志里却什么都没有。
func TestCollectTrafficKeepsBaselineForAbsentProxy(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "absentuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	proxy := FrpUserOf(u.ID) + ".mc"
	frps := newFakeFrpsTraffic(proxy)
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()

	frps.total.Store(5000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5000 {
		t.Fatalf("首轮应记 5000，实际 %d", got)
	}

	// 这一轮列表里没有这条代理：不该产生流量，基线也不能丢。
	frps.absent.Store(true)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5000 {
		t.Fatalf("代理缺席的一轮不该产生流量，实际 %d", got)
	}
	svc.Runtime.mu.RLock()
	prev, kept := svc.Runtime.lastStat[proxy]
	svc.Runtime.mu.RUnlock()
	if !kept {
		t.Fatal("短暂缺席不该丢掉采样基线：重新出现时会把当天累计值整个再记一遍")
	}
	if prev.in != 5000 {
		t.Fatalf("保留的基线值不对: got %d want 5000", prev.in)
	}

	// 重新出现：只补记新增的 300，而不是当天的 5300。
	frps.absent.Store(false)
	frps.total.Store(5300)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5300 {
		t.Fatalf("重新出现应只补记新增流量，实际 %d（丢掉基线会变成 10300）", got)
	}
}

// TestCollectTrafficResetsBaselineForRecreatedTunnel 覆盖「同名隧道删了重建」。
//
// 代理名只由「用户 ID + 隧道名」组成：删掉隧道再建一条同名的，代理名一模一样，
// 但 frps 侧的当日累计从 0 重新开始。基线若只按代理名保留，就会拿旧代理的值去
// 减新代理的计数——旧基线更大时按「跨零点」处理（把新计数整个记一遍），
// 更小时把新隧道前段的流量整段吃掉。基线带隧道行 ID 才能认出这是新代理。
func TestCollectTrafficResetsBaselineForRecreatedTunnel(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "recreateuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	proxy := FrpUserOf(u.ID) + ".mc"
	frps := newFakeFrpsTraffic(proxy)
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	newTunnel := func() *model.Tunnel {
		tun := &model.Tunnel{
			UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
			Status: model.TunnelStatusActive,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
		return tun
	}

	ctx := context.Background()
	old := newTunnel()
	frps.total.Store(5000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, old.ID); got != 5000 {
		t.Fatalf("首轮应记 5000，实际 %d", got)
	}

	// 删掉旧隧道，建一条同名的：代理名不变，但这是**新的**代理，
	// frps 侧的当日累计从 0 重新开始。
	if err := svc.DB.Delete(&model.Tunnel{}, old.ID).Error; err != nil {
		t.Fatalf("删隧道失败: %v", err)
	}
	fresh := newTunnel()
	frps.total.Store(6000)
	svc.collectTraffic(ctx)

	if got := tunnelTrafficUsed(t, svc, fresh.ID); got != 6000 {
		t.Fatalf("新隧道的当日累计应完整记入 6000，实际 %d"+
			"（沿用旧代理基线会只记 1000）", got)
	}
}

// TestCollectTrafficSkipsDeltaForLegacyBaseline 覆盖「升级前留下的基线」。
//
// 新增隧道标识列之后，旧行是零值：它可能正是同名重建之前的旧累计值。
// 直接相减会算错（少记或重记整天），所以第一次用上这种基线时不计增量——
// 最多损失一个采集周期，好过把一整天的流量算错。
func TestCollectTrafficSkipsDeltaForLegacyBaseline(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

	// 基线迁移标记：否则首轮本来就只记基线、不计增量，测不出这条规则。
	if err := svc.Settings.SetInternal(map[SettingKey]string{KeyTrafficBaselineReady: "1"}); err != nil {
		t.Fatalf("写迁移标记失败: %v", err)
	}

	u := &model.User{Username: "legacybase", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	// 旧数据：没有隧道标识的基线行。
	if err := svc.DB.Create(&model.TrafficBaseline{
		ProxyName: FrpUserOf(u.ID) + ".mc",
		Date:      time.Now().Format("2006-01-02"),
		InBytes:   5000,
	}).Error; err != nil {
		t.Fatalf("写旧基线失败: %v", err)
	}

	proxy := FrpUserOf(u.ID) + ".mc"
	frps := newFakeFrpsTraffic(proxy)
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	if !svc.loadTrafficBaseline() {
		t.Fatal("基线应能恢复")
	}

	ctx := context.Background()
	frps.total.Store(6000)
	svc.collectTraffic(ctx)

	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 0 {
		t.Fatalf("旧基线无从判断归属，这一轮不该计增量，实际记了 %d", got)
	}

	// 之后正常计增量：基线已被推进到 6000。
	frps.total.Store(6300)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 300 {
		t.Fatalf("后续应只记新增的 300，实际 %d", got)
	}
}

// TestPruneDeadBaselines 覆盖继承基线的清理口径。
//
//   - 隧道仍在、只是本轮没出现（客户端关了）→ 必须保留，否则它回来时
//     会把当天累计值整个重记一遍；
//   - 隧道行已删除 → 立即剔除，否则内存与基线表会随「当天创建过的隧道数」增长；
//   - 没有隧道标识的旧条目 → 无从判断，缺席超过保留期才剔除。
func TestPruneDeadBaselines(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "prunebase", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	alive := &model.Tunnel{
		UserID: u.ID, Name: "alive", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 1, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(alive).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	now := time.Now()
	nextStat := map[string]trafficPair{
		"lt_u1.alive":  {in: 100, seenAt: now, tunnelID: alive.ID}, // 隧道仍在
		"lt_u1.dead":   {in: 200, seenAt: now, tunnelID: 999999},   // 隧道已删
		"lt_u1.legacy": {in: 300, seenAt: now.Add(-2 * time.Hour)}, // 旧数据，缺席超期
		"lt_u1.recent": {in: 400, seenAt: now.Add(-time.Minute)},   // 旧数据，还在保留期
	}
	svc.pruneDeadBaselines(nextStat, map[string]bool{}, now)

	if _, ok := nextStat["lt_u1.alive"]; !ok {
		t.Fatal("隧道仍在、只是暂时离线的基线必须保留")
	}
	if _, ok := nextStat["lt_u1.dead"]; ok {
		t.Fatal("隧道已删除的基线应被剔除")
	}
	if _, ok := nextStat["lt_u1.legacy"]; ok {
		t.Fatal("旧数据缺席超过保留期应被剔除")
	}
	if _, ok := nextStat["lt_u1.recent"]; !ok {
		t.Fatal("旧数据仍在保留期内应保留")
	}
}

// TestTrafficCollectorLeaseKeepsSingleWriter 覆盖「多实例各自采集导致重复记账」。
//
// 每个面板进程都会启动采集器：各自从 frps 读同一份累计值、各自算增量、
// 各自累加——同一段流量被记两遍。进程内的 Runtime.mu 管不到别的进程，
// 所以用数据库里的租约把「谁采集」收敛成一个。
func TestTrafficCollectorLeaseKeepsSingleWriter(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "leaseuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20091,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("首个实例应记 1000，实际 %d", got)
	}

	// 第二个实例（同一个库）：这一轮拿不到租约，必须完全跳过。
	//
	// 注意这里**不**手动读基线：接管时 collectTraffic 自己会按库里的最新值
	// 重建（否则会拿启动时的旧基线，把别人已经记过的流量再记一遍）。
	second := New(svc.DB, cfg)
	second.Frps = NewFrpsClient(cfg)
	frps.total.Store(1200)
	second.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, second, tun.ID); got != 1000 {
		t.Fatalf("拿不到租约的实例不该记账（会重复计费），实际 %d", got)
	}

	// 租约到期后接手：只补记新增的 200，不把当天累计重记一遍。
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	second.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, second, tun.ID); got != 1200 {
		t.Fatalf("接手后应只补记新增流量，实际 %d", got)
	}
}

// TestBaselineReadFailureReleasesLease 覆盖「读基线失败却仍算持有采集权」。
//
// 先置 collectorOwned 再读基线的话，读失败返回后标记仍是 true：下一轮租约还在
// 自己手里，于是跳过重读，拿**过期的内存基线**算增量——重复计费。
func TestBaselineReadFailureReleasesLease(t *testing.T) {
	svc := newTestServices(t, nil)

	// 删掉基线表，让 loadTrafficBaseline 失败。
	if err := svc.DB.Migrator().DropTable(&model.TrafficBaseline{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	svc.collectTraffic(context.Background())

	if svc.collectorOwned.Load() {
		t.Fatal("基线读不到时不能算「已持有采集权」，否则下一轮会跳过重读")
	}

	var lease model.RuntimeLease
	if err := svc.DB.Where("name = ?", leaseTrafficCollector).First(&lease).Error; err != nil {
		t.Fatalf("读租约失败: %v", err)
	}
	if lease.ExpiresAt.After(time.Now()) {
		t.Fatal("读基线失败时应交还租约，让下一轮重新走接管流程")
	}
}

// TestTrafficResetMarkSeedSkipsFirstRound 覆盖「旧库升级时标记表还是空的」。
//
// 基线就绪不代表标记就绪：旧库有基线、没有标记表。若停机期间清零过，
// 首轮会把「没有记录」当成「代次没变」，把清零前的流量加回来。
// 首轮按保守策略跳过增量，并落下标记。
func TestTrafficResetMarkSeedSkipsFirstRound(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	// 只声明基线已就绪，**不**声明清零代次标记就绪——模拟旧库升级。
	if err := svc.Settings.SetInternal(map[SettingKey]string{KeyTrafficBaselineReady: "1"}); err != nil {
		t.Fatalf("写基线标记失败: %v", err)
	}

	u := &model.User{Username: "resetseed", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20131,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 0 {
		t.Fatalf("清零代次标记首次启用时，首轮不该计增量，实际 %d", got)
	}
	if !svc.Settings.Bool(KeyTrafficResetMarkReady) {
		t.Fatal("首轮成功后应落下清零代次迁移标记")
	}

	frps.total.Store(1300)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 300 {
		t.Fatalf("第二轮应正常计增量 300，实际 %d", got)
	}
}

// TestTrafficResetMarkSeedCoversOfflineUsers 覆盖「升级时正好离线的用户」。
//
// 只把本轮采样到的用户写进标记表是不够的：升级时离线的用户不会被采样，
// 等它下次上线时基线还是升级前那份，而「没有标记」会被当成「代次没变」，
// 升级前（甚至停机期间）的清零就识别不出来。迁移时应把所有用户记为
// 「代次未知」，并**落库**——只放内存的话，控制面重启一次就又回到老问题。
func TestTrafficResetMarkSeedCoversOfflineUsers(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	// 旧库升级：基线已就绪，标记表为空。
	if err := svc.Settings.SetInternal(map[SettingKey]string{KeyTrafficBaselineReady: "1"}); err != nil {
		t.Fatalf("写基线标记失败: %v", err)
	}

	online := &model.User{Username: "seedonline", Password: "not-used", Status: model.UserStatusActive}
	offline := &model.User{Username: "seedoffline", Password: "not-used", Status: model.UserStatusActive}
	for _, u := range []*model.User{online, offline} {
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
	}
	onlineTun := &model.Tunnel{
		UserID: online.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20133,
		Status: model.TunnelStatusActive,
	}
	offlineTun := &model.Tunnel{
		UserID: offline.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20134,
		Status: model.TunnelStatusActive,
	}
	for _, tun := range []*model.Tunnel{onlineTun, offlineTun} {
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}
	// 升级前留下的基线：离线用户这条代理当时还在跑。
	offlineProxy := FrpUserOf(offline.ID) + ".mc"
	if err := svc.DB.Create(&model.TrafficBaseline{
		ProxyName: offlineProxy, Date: time.Now().Format("2006-01-02"),
		InBytes: 500, TunnelID: offlineTun.ID,
	}).Error; err != nil {
		t.Fatalf("写旧基线失败: %v", err)
	}

	// 播种轮：frps 只上报在线用户，离线用户这一轮不会被采样。
	frps := newFakeFrpsTraffic(FrpUserOf(online.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)
	frps.total.Store(1000)
	svc.collectTraffic(context.Background())
	if !svc.Settings.Bool(KeyTrafficResetMarkReady) {
		t.Fatal("播种轮后应落下清零代次迁移标记")
	}

	// 离线用户的标记必须是「未知」哨兵，而且已经落库。
	var mark model.TrafficResetMark
	if err := svc.DB.Where("user_id = ?", offline.ID).First(&mark).Error; err != nil {
		t.Fatalf("离线用户的标记应已写入: %v", err)
	}
	if mark.Gen != resetGenUnknown {
		t.Fatalf("离线用户应记为代次未知 %d，实际 %d", resetGenUnknown, mark.Gen)
	}

	// 控制面重启：哨兵必须能从库里读回来。
	restarted := New(svc.DB, cfg)
	restarted.Frps = NewFrpsClient(cfg)
	if !restarted.loadTrafficBaseline() {
		t.Fatal("基线应能恢复")
	}
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatalf("释放采集租约失败: %v", err)
	}

	// 离线用户上线：这一轮增量横跨「代次未知」，必须丢弃。
	onlineFrps := newFakeFrpsTraffic(offlineProxy)
	defer onlineFrps.Close()
	cfg.FrpsAPIAddr = onlineFrps.URL
	restarted.Frps = NewFrpsClient(cfg)
	onlineFrps.total.Store(900)
	restarted.collectTraffic(context.Background())
	if got := userTrafficUsed(t, restarted, offline.ID); got != 0 {
		t.Fatalf("代次未知时这一轮增量应丢弃，实际 %d", got)
	}

	// 下一轮恢复正常：900 → 1000 只记 100。
	onlineFrps.total.Store(1000)
	restarted.collectTraffic(context.Background())
	if got := userTrafficUsed(t, restarted, offline.ID); got != 100 {
		t.Fatalf("代次确定后应正常计增量 100，实际 %d", got)
	}
}

// TestSeedUnknownResetGensReportsFailure 覆盖「播种失败却宣告迁移完成」。
//
// 播种只写进去一部分就返回的话，调用方仍会继续采集，成功后还会落下迁移
// 标记；那些没被标记的用户下次上线时仍会被当成「代次没变」，把清零前的
// 流量加回来。所以失败必须如实返回，由调用方放弃本轮、下轮重试。
func TestSeedUnknownResetGensReportsFailure(t *testing.T) {
	svc := newTestServices(t, &config.Config{})
	u := &model.User{Username: "seedfail", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	// 标记表写不进去（模拟迁移中途缺表）。
	if err := svc.DB.Migrator().DropTable(&model.TrafficResetMark{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	if err := svc.seedUnknownResetGens(map[uint]int64{}); err == nil {
		t.Fatal("写入失败时必须返回错误，否则迁移会在标记不完整的情况下被宣告完成")
	}
}

// TestPortPoolUsageMarksFreeUnknownOnDBError 覆盖「读库失败仍报空闲端口」。
//
// 已分配端口读不出来时，Free 只按「保留 + 系统占用」算：数值明显偏高，
// 管理页据此以为端口还宽裕，而实际可能早就用完了——比不显示更糟。
// 此时必须标成未知，并且不能顺手给出「仅剩 0 个」这种由错误本身造成的假警报。
func TestPortPoolUsageMarksFreeUnknownOnDBError(t *testing.T) {
	svc := newTestServices(t, &config.Config{PortRangeStart: 31000, PortRangeEnd: 31009})
	u := &model.User{Username: "poolusage", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 31005,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	usage := svc.PortPoolUsageOf()
	if usage.FreeUnknown {
		t.Fatal("读库正常时不该标记为未知")
	}
	if usage.Free >= usage.Total {
		t.Fatalf("已分配 1 个端口，可用数应小于总量 %d，实际 %d", usage.Total, usage.Free)
	}

	// 让「读已分配端口」失败。
	if err := svc.DB.Migrator().DropTable(&model.Tunnel{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	usage = svc.PortPoolUsageOf()
	if !usage.FreeUnknown {
		t.Fatal("读已分配端口失败时必须把空闲量标为未知，否则会报出一个偏高的可用量")
	}
	if usage.AllocatedError == "" {
		t.Fatal("应带上失败原因，便于管理员判断这是暂时性故障")
	}
	if usage.Free != 0 {
		t.Fatalf("未知时空闲量应为 0（是否可信由 FreeUnknown 表达），实际 %d", usage.Free)
	}
	for _, tip := range usage.Advice {
		if strings.Contains(tip, "仅剩") {
			t.Fatalf("空闲量未知时不该给「仅剩 N 个」的结论，实际提示: %s", tip)
		}
	}
}

// TestTrafficResetCrossesInstances 覆盖「清零请求落在别的实例」。
//
// 清零标记只存在进程内：多副本时请求落在 B、采集跑在 A，A 看不到那个标记，
// 仍会把清零前的旧增量加回去。清零代次存在库里，A 按它判断这一轮增量
// 是否横跨了清零点。
func TestTrafficResetCrossesInstances(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "crossreset", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20111,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 1000 {
		t.Fatalf("首轮应记 1000，实际 %d", got)
	}

	// 另一个实例执行清零（共享同一个库）。
	other := New(svc.DB, cfg)
	if err := other.AdminResetUserTraffic(u.ID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, u.ID); got != 0 {
		t.Fatalf("清零后用量应为 0，实际 %d", got)
	}

	// 采集实例下一轮：这批增量属于清零前的流量，不能再加回去。
	frps.total.Store(1200)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 0 {
		t.Fatalf("清零之后不该把旧流量加回来，实际 %d", got)
	}

	// 再下一轮：清零之后的流量要正常入账。
	frps.total.Store(1500)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 300 {
		t.Fatalf("清零后的新增流量应记 300，实际 %d", got)
	}
}

// TestTrafficResetSurvivesCollectorRestart 覆盖「清零代次只记在内存里」。
//
// 采集进程重启或换手后 lastResetGen 是空的，于是「清零发生在上次采样之后、
// 重启之前」这段窗口里的旧流量会被重新计入。代次与基线一起落库，重启后
// 读回来才能判断。
func TestTrafficResetSurvivesCollectorRestart(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "restartreset", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20121,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 1000 {
		t.Fatalf("首轮应记 1000，实际 %d", got)
	}

	// 「停机」期间：别的实例清零，同时旧采集器退出（租约待过期）。
	other := New(svc.DB, cfg)
	if err := other.AdminResetUserTraffic(u.ID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}

	// 重启后的实例：必须从库里恢复「基线对应的代次」，认出期间被清零过。
	restarted := New(svc.DB, cfg)
	restarted.Frps = NewFrpsClient(cfg)
	if !restarted.loadTrafficBaseline() {
		t.Fatal("基线应能恢复")
	}
	frps.total.Store(1200)
	restarted.collectTraffic(ctx)
	if got := userTrafficUsed(t, restarted, u.ID); got != 0 {
		t.Fatalf("重启后不该把清零前的流量加回来，实际 %d", got)
	}

	// 再下一轮：清零之后的流量正常入账（不应因为记着旧代次而再跳过一次）。
	frps.total.Store(1500)
	restarted.collectTraffic(ctx)
	if got := userTrafficUsed(t, restarted, u.ID); got != 300 {
		t.Fatalf("清零后的新增流量应记 300，实际 %d", got)
	}
}

// TestTunnelOnlineFromDatabase 覆盖「多副本下非采集实例显示离线」。
//
// 进程内的在线集合只有持有采集租约的实例会更新；接口改读 last_online_at，
// 谁读都对。
func TestTunnelOnlineFromDatabase(t *testing.T) {
	svc := newTestServices(t, nil)

	recent := time.Now().Add(-10 * time.Second)
	old := time.Now().Add(-time.Hour)

	if !svc.IsTunnelOnline(&model.Tunnel{LastOnlineAt: &recent}) {
		t.Fatal("最近上报过在线时间的隧道应判为在线")
	}
	if svc.IsTunnelOnline(&model.Tunnel{LastOnlineAt: &old}) {
		t.Fatal("很久没上报的隧道应判为离线")
	}
	if svc.IsTunnelOnline(&model.Tunnel{}) {
		t.Fatal("从未上报过的隧道应判为离线")
	}
}

// TestAcquireLeaseFencing 覆盖「租约过期后旧持有者仍能写账」。
//
// 采集可能因为 frps 慢、库慢而超过租约时长：到期后另一个实例接手并开始记账，
// 旧实例若照常落库，同一段流量会被记两遍。落库前再抢一次租约就是 fencing——
// 抢不到说明持有者已经换人，本轮结果必须丢弃。
func TestAcquireLeaseFencing(t *testing.T) {
	svc := newTestServices(t, nil)
	other := New(svc.DB, svc.Cfg)

	// 用采集租约的名字：flushTraffic 的 fencing 校验的就是这一行。
	const name = leaseTrafficCollector
	gen1, ok := svc.acquireLease(name, time.Minute)
	if !ok {
		t.Fatal("首个实例应取得租约")
	}
	// 持有者可以续租，且每次续租推进代次。
	gen2, ok := svc.acquireLease(name, time.Minute)
	if !ok || gen2 <= gen1 {
		t.Fatalf("续租应推进代次（%d → %d）", gen1, gen2)
	}
	// 租约有效期内，别的实例抢不到。
	if _, ok := other.acquireLease(name, time.Minute); ok {
		t.Fatal("租约有效期内不该被别的实例抢走")
	}

	// 模拟「旧实例卡住超过租期，另一个实例接手」。
	if err := svc.DB.Model(&model.RuntimeLease{}).Where("name = ?", name).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	gen3, ok := other.acquireLease(name, time.Minute)
	if !ok {
		t.Fatal("租约到期后应可被接手")
	}

	// 旧实例此时再想续租：必须失败（否则它会写出一份重复的账）。
	if _, ok := svc.acquireLease(name, time.Minute); ok {
		t.Fatal("已被接手的租约不该被旧持有者抢回")
	}

	// 更关键的一步：旧实例拿着旧代次落库，事务内的 fencing 必须拒绝它。
	empty := map[string]trafficPair{}
	if err := svc.flushTraffic(nil, nil, nil, empty, true, trafficFence{leaseGen: gen2}); !errors.Is(err, errLeaseLost) {
		t.Fatalf("旧代次落库应被拒绝，实际 %v", err)
	}
	// 新持有者用新代次可以正常落库。
	if err := other.flushTraffic(nil, nil, nil, empty, true, trafficFence{leaseGen: gen3}); err != nil {
		t.Fatalf("当前持有者应能落库: %v", err)
	}
}

// TestCollectTrafficKeepsBaselineWhenFlushFails 覆盖「落库失败永久漏记流量」。
//
// 采样基线（Runtime.lastStat）如果先推进、再落库，事务失败时那一轮的增量
// 就永久丢了：下一轮从已经推进过的基线算增量，中间这段流量再也不会被记上。
// 用户看到的已用量比实际少（等于配额被悄悄放宽），统计也缺一块，
// 而日志里只有一行「落库失败」。
func TestCollectTrafficKeepsBaselineWhenFlushFails(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
	markTrafficBaselineReady(t, svc)

	u := &model.User{Username: "trafficuser", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "mc", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 25565, RemotePort: 20001,
		Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(u.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)

	ctx := context.Background()

	// 1) 正常一轮：1000 字节应落库
	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("第一轮落库 = %d，期望 1000", got)
	}

	// 2) 制造落库失败：删掉按日统计表，flushTraffic 的事务会整体回滚
	if err := svc.DB.Migrator().DropTable(&model.TrafficDaily{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	frps.total.Store(2000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("落库失败的那一轮不该改动已用量（事务应整体回滚），实际 %d", got)
	}

	// 3) 恢复后下一轮必须把失败期间的增量一起补记
	if err := svc.DB.AutoMigrate(&model.TrafficDaily{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 2000 {
		t.Fatalf("恢复后应补记全部增量，实际 %d，期望 2000（少了说明采样基线被提前推进了）", got)
	}
}
