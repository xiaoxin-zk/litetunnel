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

	frps.total.Store(5000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5000 {
		t.Fatalf("首轮应记 5000，实际 %d", got)
	}

	restarted := New(svc.DB, cfg)
	restarted.Frps = NewFrpsClient(cfg)
	restarted.loadTrafficBaseline()
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatalf("释放采集租约失败: %v", err)
	}

	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5000 {
		t.Fatalf("重启后不该重复计入当天已有流量，实际 %d，期望 5000", got)
	}

	frps.total.Store(5200)
	restarted.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, restarted, tun.ID); got != 5200 {
		t.Fatalf("重启后新增流量应正常记入，实际 %d，期望 5200", got)
	}
}

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

	frps.total.Store(5000)

	if err := svc.DB.Migrator().DropTable(&model.TrafficBaseline{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartTrafficCollector(ctx)

	time.Sleep(700 * time.Millisecond)
	if svc.Runtime.IsTunnelOnline(tun.ID) {
		t.Fatal("基线不可用时不该采集（会把当天累计值整个记成新增量），本轮连在线状态都不该更新")
	}
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 0 {
		t.Fatalf("基线不可用时不该记入流量，实际已记 %d", got)
	}

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
	if !svc.Runtime.IsTunnelOnline(tun.ID) {
		t.Fatal("播种轮应正常采集在线状态")
	}
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 0 {
		t.Fatalf("首次迁移的第一轮只应写基线、不计增量，实际已记 %d（这正是要防的重复计入）", got)
	}

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

	frps.absent.Store(false)
	frps.total.Store(5300)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 5300 {
		t.Fatalf("重新出现应只补记新增流量，实际 %d（丢掉基线会变成 10300）", got)
	}
}

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

func TestCollectTrafficSkipsDeltaForLegacyBaseline(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)

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

	frps.total.Store(6300)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 300 {
		t.Fatalf("后续应只记新增的 300，实际 %d", got)
	}
}

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
		"lt_u1.alive":  {in: 100, seenAt: now, tunnelID: alive.ID},
		"lt_u1.dead":   {in: 200, seenAt: now, tunnelID: 999999},
		"lt_u1.legacy": {in: 300, seenAt: now.Add(-2 * time.Hour)},
		"lt_u1.recent": {in: 400, seenAt: now.Add(-time.Minute)},
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

	second := New(svc.DB, cfg)
	second.Frps = NewFrpsClient(cfg)
	frps.total.Store(1200)
	second.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, second, tun.ID); got != 1000 {
		t.Fatalf("拿不到租约的实例不该记账（会重复计费），实际 %d", got)
	}

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

func TestBaselineReadFailureReleasesLease(t *testing.T) {
	svc := newTestServices(t, nil)

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

func TestTrafficResetMarkSeedSkipsFirstRound(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
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

func TestTrafficResetMarkSeedCoversOfflineUsers(t *testing.T) {
	cfg := &config.Config{}
	svc := newTestServices(t, cfg)
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
	offlineProxy := FrpUserOf(offline.ID) + ".mc"
	if err := svc.DB.Create(&model.TrafficBaseline{
		ProxyName: offlineProxy, Date: time.Now().Format("2006-01-02"),
		InBytes: 500, TunnelID: offlineTun.ID,
	}).Error; err != nil {
		t.Fatalf("写旧基线失败: %v", err)
	}

	frps := newFakeFrpsTraffic(FrpUserOf(online.ID) + ".mc")
	defer frps.Close()
	cfg.FrpsAPIAddr = frps.URL
	svc.Frps = NewFrpsClient(cfg)
	frps.total.Store(1000)
	svc.collectTraffic(context.Background())
	if !svc.Settings.Bool(KeyTrafficResetMarkReady) {
		t.Fatal("播种轮后应落下清零代次迁移标记")
	}

	var mark model.TrafficResetMark
	if err := svc.DB.Where("user_id = ?", offline.ID).First(&mark).Error; err != nil {
		t.Fatalf("离线用户的标记应已写入: %v", err)
	}
	if mark.Gen != resetGenUnknown {
		t.Fatalf("离线用户应记为代次未知 %d，实际 %d", resetGenUnknown, mark.Gen)
	}

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

	onlineFrps := newFakeFrpsTraffic(offlineProxy)
	defer onlineFrps.Close()
	cfg.FrpsAPIAddr = onlineFrps.URL
	restarted.Frps = NewFrpsClient(cfg)
	onlineFrps.total.Store(900)
	restarted.collectTraffic(context.Background())
	if got := userTrafficUsed(t, restarted, offline.ID); got != 0 {
		t.Fatalf("代次未知时这一轮增量应丢弃，实际 %d", got)
	}

	onlineFrps.total.Store(1000)
	restarted.collectTraffic(context.Background())
	if got := userTrafficUsed(t, restarted, offline.ID); got != 100 {
		t.Fatalf("代次确定后应正常计增量 100，实际 %d", got)
	}
}

func TestSeedUnknownResetGensReportsFailure(t *testing.T) {
	svc := newTestServices(t, &config.Config{})
	u := &model.User{Username: "seedfail", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := svc.DB.Migrator().DropTable(&model.TrafficResetMark{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	if err := svc.seedUnknownResetGens(map[uint]int64{}); err == nil {
		t.Fatal("写入失败时必须返回错误，否则迁移会在标记不完整的情况下被宣告完成")
	}
}

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

	other := New(svc.DB, cfg)
	if err := other.AdminResetUserTraffic(u.ID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}
	if got := userTrafficUsed(t, svc, u.ID); got != 0 {
		t.Fatalf("清零后用量应为 0，实际 %d", got)
	}

	frps.total.Store(1200)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 0 {
		t.Fatalf("清零之后不该把旧流量加回来，实际 %d", got)
	}

	frps.total.Store(1500)
	svc.collectTraffic(ctx)
	if got := userTrafficUsed(t, svc, u.ID); got != 300 {
		t.Fatalf("清零后的新增流量应记 300，实际 %d", got)
	}
}

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

	other := New(svc.DB, cfg)
	if err := other.AdminResetUserTraffic(u.ID); err != nil {
		t.Fatalf("清零失败: %v", err)
	}
	if err := svc.DB.Model(&model.RuntimeLease{}).
		Where("name = ?", leaseTrafficCollector).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}

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

	frps.total.Store(1500)
	restarted.collectTraffic(ctx)
	if got := userTrafficUsed(t, restarted, u.ID); got != 300 {
		t.Fatalf("清零后的新增流量应记 300，实际 %d", got)
	}
}

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

func TestAcquireLeaseFencing(t *testing.T) {
	svc := newTestServices(t, nil)
	other := New(svc.DB, svc.Cfg)

	const name = leaseTrafficCollector
	gen1, ok := svc.acquireLease(name, time.Minute)
	if !ok {
		t.Fatal("首个实例应取得租约")
	}
	gen2, ok := svc.acquireLease(name, time.Minute)
	if !ok || gen2 <= gen1 {
		t.Fatalf("续租应推进代次（%d → %d）", gen1, gen2)
	}
	if _, ok := other.acquireLease(name, time.Minute); ok {
		t.Fatal("租约有效期内不该被别的实例抢走")
	}

	if err := svc.DB.Model(&model.RuntimeLease{}).Where("name = ?", name).
		Update("expires_at", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	gen3, ok := other.acquireLease(name, time.Minute)
	if !ok {
		t.Fatal("租约到期后应可被接手")
	}

	if _, ok := svc.acquireLease(name, time.Minute); ok {
		t.Fatal("已被接手的租约不该被旧持有者抢回")
	}

	empty := map[string]trafficPair{}
	if err := svc.flushTraffic(nil, nil, nil, empty, true, trafficFence{leaseGen: gen2}); !errors.Is(err, errLeaseLost) {
		t.Fatalf("旧代次落库应被拒绝，实际 %v", err)
	}
	if err := other.flushTraffic(nil, nil, nil, empty, true, trafficFence{leaseGen: gen3}); err != nil {
		t.Fatalf("当前持有者应能落库: %v", err)
	}
}

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

	frps.total.Store(1000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("第一轮落库 = %d，期望 1000", got)
	}

	if err := svc.DB.Migrator().DropTable(&model.TrafficDaily{}); err != nil {
		t.Fatalf("删表失败: %v", err)
	}
	frps.total.Store(2000)
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 1000 {
		t.Fatalf("落库失败的那一轮不该改动已用量（事务应整体回滚），实际 %d", got)
	}

	if err := svc.DB.AutoMigrate(&model.TrafficDaily{}); err != nil {
		t.Fatalf("重建表失败: %v", err)
	}
	svc.collectTraffic(ctx)
	if got := tunnelTrafficUsed(t, svc, tun.ID); got != 2000 {
		t.Fatalf("恢复后应补记全部增量，实际 %d，期望 2000（少了说明采样基线被提前推进了）", got)
	}
}
