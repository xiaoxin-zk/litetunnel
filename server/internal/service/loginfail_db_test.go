package service

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这一组守的是账号级失败计数的**跨实例**语义（见 loginfail_db.go）。
//
// 背景：计数原先是纯进程内 map。单实例部署没问题，但多实例共用负载均衡时，
// 同一账号的失败请求被分到不同实例，每个实例各记一份，账号级验证码阈值就按
// 实例数衰减——N 个实例等于 N 倍额度，而且没有任何报错。账号级验证码是分布式
// 爆破的唯一克星（硬锁按「账号 + IP」计数，分布式来源每个 IP 各有一份额度），
// 它被摊薄之后就没有兜底了。
//
// 因此计数落库，累加走唯一索引上的原子 upsert。下面的用例分别守住：
// 窗口内累加、窗口过期重置、并发累加不丢计数、登录成功后清零。

// newDBLoginFailCounter 造一个接了真实 sqlite 的落库版计数。
//
// 用真实库而不是替身：这里要验的正是「upsert 在两种方言下语义一致」与
// 「并发时计数不丢」，替身验不了这两点。
func newDBLoginFailCounter(t *testing.T) (*Services, *dbLoginFailureCounter) {
	t.Helper()
	svc := newTestServices(t, nil)
	c, ok := svc.loginFails.(*dbLoginFailureCounter)
	if !ok {
		t.Fatalf("接了数据库的 Services 必须使用落库版计数，实际 %T", svc.loginFails)
	}
	return svc, c
}

// TestLoginFailCounterAccumulatesWithinWindow 覆盖窗口内的累加与读取。
func TestLoginFailCounterAccumulatesWithinWindow(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-fail-user"

	if got := c.count(account, now); got != 0 {
		t.Fatalf("从未失败过的账号应为 0，实际 %d", got)
	}
	for i := 1; i <= 3; i++ {
		c.record(account, now)
		if got := c.count(account, now); got != i {
			t.Fatalf("第 %d 次失败后计数应为 %d，实际 %d", i, i, got)
		}
	}

	// 大小写与空白必须归一到同一个键：登录本身不区分大小写，不归一化的话
	// 攻击者交替提交 Admin / admin 就能把计数摊薄。
	if got := c.count("  DB-Fail-User ", now); got != 3 {
		t.Fatalf("计数键必须规范化，实际读到 %d", got)
	}
}

// TestLoginFailCounterTruncatesOverlongAccount 覆盖超长用户名的计数键。
//
// 主键列是 varchar(191)：Postgres 会直接拒绝更长的值（于是每一次超长用户名
// 登录都写库失败、退化成补记并刷告警日志），SQLite 的 TEXT 不校验长度（于是
// 攻击者能用几 KB 的用户名把计数表撑大）。两种方言都必须落在同一个上限上。
//
// 断言分两半：写入与查询用同一个截断键（否则计数永远读不回来），且库里的
// 行确实是截断后的长度。
func TestLoginFailCounterTruncatesOverlongAccount(t *testing.T) {
	svc, c := newDBLoginFailCounter(t)
	now := time.Now()
	long := strings.Repeat("超长账号", 100) // 400 个字符，远超 191

	c.record(long, now)
	c.record(long, now)
	if got := c.count(long, now); got != 2 {
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
	// 同一个前缀的不同超长账号会共用计数器：方向是「更早要求验证码」，
	// 属于可接受的失败安全侧（见 normalizeAccount 的注释）。
	if got := c.count(long+"x", now); got != 2 {
		t.Fatalf("共享同一个截断前缀的账号读到的应是同一份计数，实际 %d", got)
	}
}

// TestLoginFailCounterResetsAfterWindow 覆盖窗口过期即视为 0，且下一次失败
// 从 1 重新开始（而不是在旧值上继续加）。
//
// 这条不成立时的表现很隐蔽：账号一旦在某个窗口里攒到阈值，就会**永远**被
// 要求验证码——正常用户被长期惩罚，而界面上看不出任何异常。
func TestLoginFailCounterResetsAfterWindow(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	start := time.Now()
	const account = "db-window-user"

	c.record(account, start)
	c.record(account, start)
	if got := c.count(account, start); got != 2 {
		t.Fatalf("前置条件：窗口内应为 2 次，实际 %d", got)
	}

	// 窗口过期：读出来必须是 0（不能靠「行已被删」来表达过期）。
	after := start.Add(loginFailWindow + time.Second)
	if got := c.count(account, after); got != 0 {
		t.Fatalf("窗口过期后应视为 0，实际 %d", got)
	}

	// 过期后的第一次失败必须从 1 开始，窗口起点也随之前移。
	c.record(account, after)
	if got := c.count(account, after); got != 1 {
		t.Fatalf("过期后的首次失败应从 1 重新计数，实际 %d", got)
	}
	// 新窗口生效：再往后一点点仍在窗口内，计数继续累加。
	c.record(account, after.Add(time.Minute))
	if got := c.count(account, after.Add(time.Minute)); got != 2 {
		t.Fatalf("新窗口内应继续累加，实际 %d", got)
	}
}

// TestLoginFailCounterConcurrentRecordsDoNotLoseCounts 覆盖并发累加。
//
// 这是「先 SELECT 再 UPDATE」会挂掉、而 upsert 能过的用例：N 个 goroutine
// 同时失败时，各自读到的都是旧计数，写回后只剩一次累加。唯一索引 + 单条
// upsert 让「判断窗口 + 加一」在数据库里一次完成，冲突方走 DO UPDATE 分支。
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

	// 断言「一次都不能丢」，而不是「恰好等于 n」：写库超时但事务其实已提交时，
	// 这一次会被同时算进库里与进程内补记（见 loginfail_db.go 的 fail-closed
	// 取舍），于是计数可能多 1。多算只会让验证码早来，少算才是防线失效，
	// 所以这里只禁止「变少」。
	if got := c.count(account, now); got < n {
		t.Fatalf("并发 %d 次失败不能丢计数，实际只读到 %d", n, got)
	}
}

// TestLoginFailCounterResetClearsSharedState 覆盖登录成功清零。
//
// 清零必须落库：只清内存的话，别的实例上那条记录还在，用户刚登录成功、
// 换个实例却又要人机验证——这正是「连续失败」语义被破坏的样子。
func TestLoginFailCounterResetClearsSharedState(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-reset-user"

	c.record(account, now)
	c.record(account, now)
	c.reset(account)

	if got := c.count(account, now); got != 0 {
		t.Fatalf("登录成功后必须清零，实际 %d", got)
	}
	// 清零之后重新失败，应从 1 开始而不是接在旧计数后面。
	c.record(account, now)
	if got := c.count(account, now); got != 1 {
		t.Fatalf("清零后的首次失败应为 1，实际 %d", got)
	}
}

// TestLoginFailCounterSharedAcrossInstances 是多实例场景的最小复现：
// 两个 Services（各自一个计数对象，模拟两个进程）共用一个库，失败次数必须
// 累加到同一份计数上。
//
// 这条用例是这次改动的核心断言：进程内计数在这里必然是 1（每个实例只看到
// 自己那一次），落库版必须是 2。
func TestLoginFailCounterSharedAcrossInstances(t *testing.T) {
	svcA, cA := newDBLoginFailCounter(t)
	// 第二个实例：同一个库、另一个 Services。newTestServices 会自己建库，
	// 所以这里手工拼一个只带 DB 的计数，等价于「另一个进程连同一个库」。
	cB := newLoginFailureCounter(svcA.DB)
	dbB, ok := cB.(*dbLoginFailureCounter)
	if !ok {
		t.Fatalf("接库的计数必须是落库版，实际 %T", cB)
	}

	now := time.Now()
	const account = "db-shared-user"

	cA.record(account, now)
	dbB.record(account, now)

	if got := cA.count(account, now); got != 2 {
		t.Fatalf("两个实例的失败必须累加到同一份计数（期望 2），实际 %d", got)
	}
	if got := dbB.count(account, now); got != 2 {
		t.Fatalf("另一个实例读到的也必须是同一份计数（期望 2），实际 %d", got)
	}

	// 在一个实例上登录成功，另一个实例也必须立刻看到清零。
	cA.reset(account)
	if got := dbB.count(account, now); got != 0 {
		t.Fatalf("清零必须跨实例生效，另一个实例仍读到 %d", got)
	}
}

// TestPurgeExpiredLoginFails 覆盖后台清理：过期行被删除，未过期的保留。
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

// TestPurgeExpiredLoginFailsInBatches 覆盖「过期行超过一批」时的分批清理。
//
// 分批不是性能优化而是必须的：这条表的主键是 account、没有自增 id，一条
// DELETE 清几十万行会长时间占住写锁（SQLite 更是整库阻塞），而登录路径上
// 恰好也在写这张表——攻击者用海量随机用户名灌表时，清理本身就会变成一次
// 自我拒绝服务。所以这里断言「跨批次也能清干净」，避免以后有人把它改回
// 一条语句。
func TestPurgeExpiredLoginFailsInBatches(t *testing.T) {
	svc, _ := newDBLoginFailCounter(t)
	now := time.Now()
	oldSince := now.Add(-2 * loginFailWindow).Unix()

	// 比单批上限多一条，确保至少走两轮。
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

// TestLoginFailCounterCountsWriteFailureInProcess 覆盖写库失败时的 fail-closed。
//
// 数据库写不进去（只读副本、锁等待超时、库已关闭）时，如果把这次失败直接丢掉，
// 就等于「数据库抖动 → 账号级防线关掉」，而抖动恰好可能出现在攻击期间。
// 所以写失败必须退化成进程内补记，判定仍然生效。
//
// 这里直接关掉连接造出写失败：sqlite 文件还在，但任何语句都会报
// 「database is closed」。
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

	// 前置条件：库确实写不进去了（否则这条用例什么也没验到）。
	if _, err := c.read(account, now); err == nil {
		t.Fatal("前置条件：连接已关闭，读库应当失败")
	}
	if got := c.count(account, now); got != 2 {
		t.Fatalf("写库失败时必须按进程内补记计数（期望 2），实际 %d", got)
	}

	// 补记同样按窗口过期：数据库长时间不可用时不能把账号永久卡在阈值上。
	if got := c.count(account, now.Add(loginFailWindow+time.Second)); got != 0 {
		t.Fatalf("补记也要按窗口过期，实际 %d", got)
	}
}

// TestLoginFailCounterAddsMissedOnTopOfDB 覆盖补记与库内计数的叠加口径。
//
// 补记只代表「没能写进库的那几次失败」，所以读出来必须是「库内 + 补记」。
// 这里刻意不把「写成功后清空补记」当作正确行为：并发下 A 写失败记进补记、
// B 紧接着写成功并清空补记，A 那次就彻底丢了。多算一次只会让验证码早来，
// 少算一次则是防线失效——方向不能反。
func TestLoginFailCounterAddsMissedOnTopOfDB(t *testing.T) {
	_, c := newDBLoginFailCounter(t)
	now := time.Now()
	const account = "db-missed-user"

	// 一次写成功（进库），再塞一条补记（模拟另一次写失败）。
	c.record(account, now)
	c.missed.record(account, now)

	if got := c.count(account, now); got != 2 {
		t.Fatalf("读取应为「库内 1 + 补记 1」，实际 %d", got)
	}

	// 登录成功要同时清掉两侧，否则清零后还会被补记顶回阈值。
	c.reset(account)
	if got := c.count(account, now); got != 0 {
		t.Fatalf("清零必须同时清掉补记，实际 %d", got)
	}
}

// TestMemoryLoginFailureCounterFallback 覆盖没有数据库句柄时的退化路径。
//
// 后台协程会构造只带部分字段的 Services（见 recovery.go），那些实例没有 DB；
// 此时必须退化为进程内计数而不是 panic，也不能返回 nil（nil 会让
// CaptchaRequired 的判定整个失效）。
func TestMemoryLoginFailureCounterFallback(t *testing.T) {
	c := newLoginFailureCounter(nil)
	if _, ok := c.(*memoryLoginFailureCounter); !ok {
		t.Fatalf("db 为 nil 时应退化为进程内计数，实际 %T", c)
	}

	now := time.Now()
	c.record("mem-user", now)
	c.record("mem-user", now)
	if got := c.count("mem-user", now); got != 2 {
		t.Fatalf("进程内计数应正常累加，实际 %d", got)
	}
	if got := c.count("mem-user", now.Add(loginFailWindow+time.Second)); got != 0 {
		t.Fatalf("进程内计数同样要按窗口过期，实际 %d", got)
	}
	c.reset("mem-user")
	if got := c.count("mem-user", now); got != 0 {
		t.Fatalf("进程内计数应可清零，实际 %d", got)
	}

	// 后台清理入口在退化路径上必须是安全的空操作：进程内实现没有落库行，
	// 返回非 0 说明它去动了别人的表；panic 则会让维护协程整个停掉。
	if got := (&Services{loginFails: c}).PurgeExpiredLoginFails(now, now.Add(time.Minute)); got != 0 {
		t.Fatalf("进程内实现没有可清理的落库行，应返回 0，实际 %d", got)
	}
}
