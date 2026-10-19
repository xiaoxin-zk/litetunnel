package service

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

func newDBLoginFailCounter(t *testing.T) (*Services, *dbLoginFailureCounter) {
	t.Helper()
	svc := newTestServices(t, nil)
	c, ok := svc.loginFails.(*dbLoginFailureCounter)
	if !ok {
		t.Fatalf("接了数据库的 Services 必须使用落库版计数，实际 %T", svc.loginFails)
	}
	return svc, c
}

func mustCount(t *testing.T, c loginFailCounter, account string, now time.Time) int {
	t.Helper()
	n, ok := c.count(account, now)
	if !ok {
		t.Fatalf("计数读取不可信（ok=false），本用例要求数据库可读: account=%q", account)
	}
	return n
}

func TestLoginFailCounterAccumulatesWithinWindow(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-fail-user"

	if got := mustCount(t, c, account, now); got != 0 {
		t.Fatalf("从未失败过的账号应为 0，实际 %d", got)
	}
	for i := 1; i <= 3; i++ {
		c.record(account, now)
		if got := mustCount(t, c, account, now); got != i {
			t.Fatalf("第 %d 次失败后计数应为 %d，实际 %d", i, i, got)
		}
	}

	if got := mustCount(t, c, "  DB-Fail-User ", now); got != 3 {
		t.Fatalf("计数键必须规范化，实际读到 %d", got)
	}
}

func TestLoginFailCounterTruncatesOverlongAccount(t *testing.T) {
	svc, c := newDBLoginFailCounter(t)
	now := time.Now()
	long := strings.Repeat("超长账号", 100)

	c.record(long, now)
	c.record(long, now)
	if got := mustCount(t, c, long, now); got != 2 {
		t.Fatalf("超长账号也必须能读回自己的计数（期望 2），实际 %d", got)
	}

	var rows []model.LoginFailCounter
	if err := svc.DB.Find(&rows).Error; err != nil {
		t.Fatalf("读取计数表失败: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("超长账号应只落一行，实际 %d 行", len(rows))
	}
	if n := len([]rune(rows[0].Account)); n != loginFailMaxKeyRunes {
		t.Fatalf("落库的账号键应截断到 %d 个字符，实际 %d", loginFailMaxKeyRunes, n)
	}
	if got := mustCount(t, c, long+"x", now); got != 2 {
		t.Fatalf("共享同一个截断前缀的账号读到的应是同一份计数，实际 %d", got)
	}
}

func TestLoginFailCounterResetsAfterWindow(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	start := time.Now()
	const account = "db-window-user"

	c.record(account, start)
	c.record(account, start)
	if got := mustCount(t, c, account, start); got != 2 {
		t.Fatalf("前置条件：窗口内应为 2 次，实际 %d", got)
	}

	after := start.Add(loginFailWindow + time.Second)
	if got := mustCount(t, c, account, after); got != 0 {
		t.Fatalf("窗口过期后应视为 0，实际 %d", got)
	}

	c.record(account, after)
	if got := mustCount(t, c, account, after); got != 1 {
		t.Fatalf("过期后的首次失败应从 1 重新计数，实际 %d", got)
	}
	c.record(account, after.Add(time.Minute))
	if got := mustCount(t, c, account, after.Add(time.Minute)); got != 2 {
		t.Fatalf("新窗口内应继续累加，实际 %d", got)
	}
}

func TestLoginFailCounterConcurrentRecordsDoNotLoseCounts(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const (
		account = "db-concurrent-user"
		n       = 40
	)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c.record(account, now)
		}()
	}
	wg.Wait()

	if got := mustCount(t, c, account, now); got < n {
		t.Fatalf("并发 %d 次失败不能丢计数，实际只读到 %d", n, got)
	}
}

func TestLoginFailCounterResetClearsSharedState(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-reset-user"

	c.record(account, now)
	c.record(account, now)
	c.reset(account)

	if got := mustCount(t, c, account, now); got != 0 {
		t.Fatalf("登录成功后必须清零，实际 %d", got)
	}
	c.record(account, now)
	if got := mustCount(t, c, account, now); got != 1 {
		t.Fatalf("清零后的首次失败应为 1，实际 %d", got)
	}
}

func TestLoginFailCounterSharedAcrossInstances(t *testing.T) {
	svcA, cA := newDBLoginFailCounter(t)
	cB := newLoginFailureCounter(svcA.DB)
	dbB, ok := cB.(*dbLoginFailureCounter)
	if !ok {
		t.Fatalf("接库的计数必须是落库版，实际 %T", cB)
	}

	now := time.Now()
	const account = "db-shared-user"

	cA.record(account, now)
	dbB.record(account, now)

	if got := mustCount(t, cA, account, now); got != 2 {
		t.Fatalf("两个实例的失败必须累加到同一份计数（期望 2），实际 %d", got)
	}
	if got := mustCount(t, dbB, account, now); got != 2 {
		t.Fatalf("另一个实例读到的也必须是同一份计数（期望 2），实际 %d", got)
	}

	cA.reset(account)
	if got := mustCount(t, dbB, account, now); got != 0 {
		t.Fatalf("清零必须跨实例生效，另一个实例仍读到 %d", got)
	}
}

func TestPurgeExpiredLoginFails(t *testing.T) {
	svc, c := newDBLoginFailCounter(t)
	now := time.Now()

	c.record("old-user", now.Add(-2*loginFailWindow))
	c.record("new-user", now)

	if got := svc.PurgeExpiredLoginFails(now.Add(-loginFailWindow), time.Now().Add(time.Minute)); got != 1 {
		t.Fatalf("应只清理 1 条过期行，实际 %d", got)
	}

	var left []model.LoginFailCounter
	if err := svc.DB.Find(&left).Error; err != nil {
		t.Fatalf("读取计数表失败: %v", err)
	}
	if len(left) != 1 || left[0].Account != "new-user" {
		t.Fatalf("窗口内的计数不能被清掉，实际 %+v", left)
	}
}

func TestPurgeExpiredLoginFailsInBatches(t *testing.T) {
	svc, _ := newDBLoginFailCounter(t)
	now := time.Now()
	oldSince := now.Add(-2 * loginFailWindow).Unix()

	n := maintenanceBatchSize + 1
	rows := make([]model.LoginFailCounter, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, model.LoginFailCounter{
			Account: fmt.Sprintf("batch-user-%d", i), Count: 1, Since: oldSince,
		})
	}
	if err := svc.DB.CreateInBatches(&rows, 100).Error; err != nil {
		t.Fatalf("批量写入过期计数失败: %v", err)
	}

	if got := svc.PurgeExpiredLoginFails(now.Add(-loginFailWindow), time.Now().Add(time.Minute)); got != int64(n) {
		t.Fatalf("跨批次的过期行也应全部清掉（期望 %d），实际 %d", n, got)
	}
	var left int64
	if err := svc.DB.Model(&model.LoginFailCounter{}).Count(&left).Error; err != nil {
		t.Fatalf("统计计数表失败: %v", err)
	}
	if left != 0 {
		t.Fatalf("清理后不该剩下过期行，实际 %d", left)
	}
}

func TestLoginFailCounterCountsWriteFailureInProcess(t *testing.T) {
	svc, c := newDBLoginFailCounter(t)
	sqlDB, err := svc.DB.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	now := time.Now()
	const account = "db-writefail-user"

	c.record(account, now)
	c.record(account, now)

	if _, err := c.read(account, now); err == nil {
		t.Fatal("前置条件：连接已关闭，读库应当失败")
	}
	got, ok := c.count(account, now)
	if got != 2 {
		t.Fatalf("写库失败时必须按进程内补记计数（期望 2），实际 %d", got)
	}
	if ok {
		t.Fatal("读库失败时不能报告「可信」：那正是缺陷 6 的降级路径")
	}

	got, _ = c.count(account, now.Add(loginFailWindow+time.Second))
	if got != 0 {
		t.Fatalf("补记也要按窗口过期，实际 %d", got)
	}
}

func TestLoginFailCounterAddsMissedOnTopOfDB(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-missed-user"

	c.record(account, now)
	c.missed.record(account, now)

	if got := mustCount(t, c, account, now); got != 2 {
		t.Fatalf("读取应为「库内 1 + 补记 1」，实际 %d", got)
	}

	c.reset(account)
	if got := mustCount(t, c, account, now); got != 0 {
		t.Fatalf("清零必须同时清掉补记，实际 %d", got)
	}
}

func TestMemoryLoginFailureCounterFallback(t *testing.T) {
	c := newLoginFailureCounter(nil)
	if _, ok := c.(*memoryLoginFailureCounter); !ok {
		t.Fatalf("db 为 nil 时应退化为进程内计数，实际 %T", c)
	}

	now := time.Now()
	c.record("mem-user", now)
	c.record("mem-user", now)
	if got := mustCount(t, c, "mem-user", now); got != 2 {
		t.Fatalf("进程内计数应正常累加，实际 %d", got)
	}
	if got := mustCount(t, c, "mem-user", now.Add(loginFailWindow+time.Second)); got != 0 {
		t.Fatalf("进程内计数同样要按窗口过期，实际 %d", got)
	}
	c.reset("mem-user")
	if got := mustCount(t, c, "mem-user", now); got != 0 {
		t.Fatalf("进程内计数应可清零，实际 %d", got)
	}

	if got := (&Services{loginFails: c}).PurgeExpiredLoginFails(now, now.Add(time.Minute)); got != 0 {
		t.Fatalf("进程内实现没有可清理的落库行，应返回 0，实际 %d", got)
	}
}

func newDegradableLoginFailCounter(t *testing.T) (*Services, *dbLoginFailureCounter, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		Env:          "test",
		LogLevel:     "warn",
		DBDriver:     "sqlite",
		DBDSN:        filepath.Join(t.TempDir(), "degrade.db"),
		APIKeyEncKey: "test-api-key-enc-key",
	}
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	svc := New(db, cfg)
	c, ok := svc.loginFails.(*dbLoginFailureCounter)
	if !ok {
		t.Fatalf("接了数据库的 Services 必须使用落库版计数，实际 %T", svc.loginFails)
	}
	return svc, c, cfg
}

func TestLoginFailCounterReadFailureFailsClosed(t *testing.T) {
	svc, c, cfg := newDegradableLoginFailCounter(t)
	if err := svc.Settings.SetMany(map[SettingKey]string{KeyLoginCaptchaAfter: "3"}); err != nil {
		t.Fatalf("设置阈值失败: %v", err)
	}

	now := time.Now()
	const account = "degrade-user"

	c.record(account, now)
	if n, ok := c.count(account, now); !ok || n != 1 {
		t.Fatalf("前置条件：库可读时应读到 1 次且可信（n=%d ok=%v）", n, ok)
	}
	if svc.CaptchaRequired("login", account) {
		t.Fatal("前置条件：只失败 1 次、阈值 3，不该要求验证码")
	}
	if svc.LoginFailDegraded() {
		t.Fatal("前置条件：库正常时不该处于降级状态")
	}

	sqlDB, err := svc.DB.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	n, ok := c.count(account, now)
	if ok {
		t.Fatal("读库失败时不能报告「可信」：那会让调用方拿 0 去比阈值")
	}
	if n != 0 {
		t.Fatalf("本实例没有写失败的补记，读到的补记数应为 0，实际 %d", n)
	}

	if !svc.CaptchaRequired("login", account) {
		t.Fatal("计数读不出来时必须要求验证码（fail-closed），否则数据库抖动就等于关掉账号级防线")
	}

	if !svc.LoginFailDegraded() {
		t.Fatal("读失败后降级标志必须置位，供健康检查/管理页展示")
	}
	if got := svc.LoginFailDegradedTotal(); got != 2 {
		t.Fatalf("降级计数应累计到 2（count + CaptchaRequired 各读失败一次），实际 %d", got)
	}

	db2, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("重新打开数据库失败: %v", err)
	}
	sqlDB2, err := db2.DB()
	if err != nil {
		t.Fatalf("取新数据库连接失败: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB2.Close() })
	c.db = db2

	n, ok = c.count(account, now)
	if !ok {
		t.Fatal("数据库恢复后读数必须重新变得可信")
	}
	if n != 1 {
		t.Fatalf("恢复后应读到库里那 1 次失败，实际 %d", n)
	}
	if svc.LoginFailDegraded() {
		t.Fatal("数据库恢复后降级标志必须清除，否则账号会被永久要求验证码")
	}
	if got := svc.LoginFailDegradedTotal(); got != 2 {
		t.Fatalf("累计降级次数不该被清零，期望仍为 2，实际 %d", got)
	}
	if svc.CaptchaRequired("login", account) {
		t.Fatal("恢复且未达阈值时不该要求验证码")
	}
}

func TestLoginFailDegradedIsFalseWithoutDB(t *testing.T) {
	mem := &Services{loginFails: newLoginFailureCounter(nil)}
	if mem.LoginFailDegraded() {
		t.Fatal("进程内计数不存在「读不到」的状态，不该报告降级")
	}
	if got := mem.LoginFailDegradedTotal(); got != 0 {
		t.Fatalf("进程内计数的降级次数应为 0，实际 %d", got)
	}
	var nilSvc *Services
	if nilSvc.LoginFailDegraded() || nilSvc.LoginFailDegradedTotal() != 0 {
		t.Fatal("nil Services 上查询降级状态必须安全返回零值")
	}
	if (&Services{}).LoginFailDegraded() {
		t.Fatal("loginFails 为 nil 时不该报告降级")
	}
}
