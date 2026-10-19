package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 本文件是账号级登录失败计数的**数据库版**实现（见 loginfail.go 的
// loginFailCounter 接口）。
//
// # 为什么默认落库
//
// 进程内计数有一个致命前提：整个系统只有一个进程。一旦前面挂了负载均衡，
// 同一账号的失败请求被分到 N 个实例，每个实例各记一份，账号级验证码阈值
// 就按实例数衰减——攻击者拿到 N 倍额度，而且**没有任何报错或指标**提示
// 防线已经变弱。账号级验证码恰恰是分布式爆破的唯一克星（硬锁按「账号+IP」
// 计数，分布式来源每个 IP 各有一份额度），所以它的数据源必须跨实例共享。
//
// 落库之后，多实例共用同一个库即天然共享同一份计数；单实例部署也照样正确，
// 只是多了一次主键级的读写。
//
// # 热路径上的代价
//
// 这个计数在每次登录失败时写一次、每次登录尝试时读一次。因此：
//   - 写用唯一索引（account 是主键）+ 单条 upsert，不存在全表扫描，
//     也不存在「先查后写」的竞态；
//   - 读是主键等值查询；
//   - 两者都带独立超时，失败不阻塞登录判定。
//
// # 写库失败时怎么办（fail-closed 的选择）
//
// 写库失败（超时、库只读、锁等待超时）：这一次累加**不能丢**，否则「数据库
// 写不进去」就等于「账号级防线关掉」。所以失败的次数记在进程内的补记表
// （missed）里，读的时候把补记数加到库里的计数上（见 count）。补记表按同一
// 个 30 分钟窗口过期，不会永久膨胀。
//
// 补记刻意**不**在后续写成功时清空：并发下 A 写失败记进补记、B 紧接着写
// 成功并清空补记，A 那次就彻底消失了。不清的唯一代价是「写失败但事务其实
// 已提交」这种边界情况下多算一次——方向是「更早要求验证码」，属于可接受的
// 失败安全侧。
//
// 读库失败：只回落到补记表。这里刻意**不**缓存历史计数到进程内——那会让
// 别的实例上的「登录成功清零」失效（本实例还拿着旧值继续要求验证码）。
//
// 这不算「完全无损」：数据库长时间不可用时跨实例的累加确实会退化成本实例
// 计数，但方向一致——宁可多要一次验证码，也不因为数据库抖动把防线放过去。
// 这类降级都会限流打日志（见 logThrottled），不会静默发生。

const (
	// loginFailDBTimeout 是单次计数读/写的时间上限。
	//
	// 压得比较短：它在登录路径上，数据库不健康时不该让用户跟着等；而窗口是
	// 30 分钟，丢一次计数最多让验证码晚来一次，代价远小于拖住一次登录。
	loginFailDBTimeout = 1500 * time.Millisecond

	// loginFailLogInterval 是同类数据库错误的日志间隔上限。
	//
	// 攻击进行中恰好数据库抖动时，每次失败都打一行日志会把磁盘打满、也会
	// 淹没真正的错误。按错误类型各自限流到每分钟一行。
	loginFailLogInterval = time.Minute
)

// errLoginFailCounterDegraded 是「失败计数暂时不可信」时的哨兵错误。
//
// 不用它做错误串拼接：count 走的是 (int, bool) 而不是 error 返回，
// 因为这里的调用方（CaptchaRequired）需要的是一个明确的布尔判断，
// 而不是去 errors.Is 一个字符串。保留它是为了让日志与测试有共同的锚点：
// 日志里用它说明「这不是某个具体数据库错误，而是降级本身」。
var errLoginFailCounterDegraded = errors.New("账号级失败计数已降级：跨实例计数不可读")

// dbLoginFailureCounter 是落库版计数。
type dbLoginFailureCounter struct {
	db *gorm.DB

	// missed 记录「写库失败、只记在本实例」的失败次数。
	//
	// 它只在写库失败时才有内容，是 fail-closed 的兜底：没有它，数据库写不
	// 进去（只读副本、锁等待超时）时攻击者的每一次失败都会被丢掉，账号级
	// 防线静默失效。按同一个 30 分钟窗口过期。
	//
	// 不复用为「读缓存」：缓存历史计数会让别的实例上的登录成功清零失效。
	missed *memoryLoginFailureCounter

	// 两类错误各自限流，避免抖动期间刷日志。
	lastWriteErrAt atomic.Int64
	lastReadErrAt  atomic.Int64

	// degraded 表示「最近一次读库失败了，跨实例计数暂时不可信」。
	//
	// 这个标志是给**外部观察者**的（健康检查、管理页）：原先降级只体现为
	// 一行限流日志，而日志会被滚动掉、也没人会去翻。一个能被查询的状态
	// 才能让运维知道「这段时间账号级阈值只在单实例内成立」。
	//
	// 只在读成功后清除（见 markRecovered）：一次成功的读就说明库又看得见了。
	degraded atomic.Bool

	// degradedTotal 是累计降级次数（读库失败次数）。
	//
	// 与布尔标志的区别：标志回答「现在是否降级」，计数回答「降级有多频繁」。
	// 反复抖动（每次都在阈值窗口内被攻击者利用）与一次瞬时故障，在运维
	// 判断上是完全不同的事，而布尔值区分不了。
	//
	// 不清零：它是历史事实，清掉等于掩盖「这里曾经不稳定」。
	degradedTotal atomic.Int64
}

// newLoginFailureCounter 构造账号级失败计数。
//
// db 为 nil 时退化为纯进程内实现：只有不接数据库的构造路径（例如后台
// 协程里那个只带部分字段的 Services）才会走到这里。
func newLoginFailureCounter(db *gorm.DB) loginFailCounter {
	if db == nil {
		return newMemoryLoginFailureCounter()
	}
	return &dbLoginFailureCounter{db: db, missed: newMemoryLoginFailureCounter()}
}

// record 记一次失败：先落库，落库失败再补记到进程内。
func (c *dbLoginFailureCounter) record(account string, now time.Time) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}
	if err := c.bump(account, now); err != nil {
		// 落库失败也要算这一次：否则「数据库写不进去」就等于「防线关掉」。
		//
		// 补记**不**在后续写成功时清除。清掉看似能避免重复计数，实际会丢
		// 计数：并发下 A 写失败记进补记、B 紧接着写成功并清空补记，A 那次
		// 就彻底消失了。而不清的唯一代价是「写失败但事务其实已提交」这种
		// 边界情况下多算一次——方向是「更早要求验证码」，属于可接受的失败
		// 安全侧。补记自己按同一个窗口过期（见 missed 的类型）。
		c.missed.record(account, now)
		c.logThrottled(&c.lastWriteErrAt, "写入", err)
	}
}

// bump 用一条 upsert 完成「窗口内累加 / 窗口过期重置」。
//
// 为什么不先 SELECT 再 UPDATE：两个实例同时失败时，各自读到的都是旧计数，
// 写回后只剩一次累加（丢失更新）。upsert 让「判断窗口 + 加一」在数据库里
// 一次完成，唯一索引（account）保证并发冲突只有一个赢家，输的那个走
// DO UPDATE 分支，计数不丢。
//
// 窗口判断在**数据库里**完成（CASE WHEN "since" <= cutoff），cutoff 由 Go
// 侧算好再作为整数参数传入：不在 SQL 里做时间减法，因为两种方言的时间函数
// 与存储格式不同；传整数则两边都是纯数值比较。这也是 Since 用 Unix 秒而
// 不是 time.Time 的原因（见 model.LoginFailCounter.Since 的注释）。
func (c *dbLoginFailureCounter) bump(account string, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()

	cutoff := now.Add(-loginFailWindow).Unix()
	row := model.LoginFailCounter{Account: account, Count: 1, Since: now.Unix()}
	return c.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account"}},
		// 两个 CASE 都读**旧行**的 since（SQLite 与 Postgres 的 DO UPDATE 都是
		// 这个语义），所以它们之间没有先后依赖，用 map 形式的 Assignments 即可
		// （它会按列名排序，正好与仓库里其它条件 upsert 的写法一致）。
		DoUpdates: clause.Assignments(map[string]any{
			// 窗口已过期（since <= cutoff）就重新从 1 开始并把窗口起点推到 now，
			// 否则在原计数上加一。两个 CASE 必须用同一个 cutoff，否则可能出现
			// 「计数重置了、窗口起点没重置」这种把账号永久卡在阈值下的状态。
			//
			// 列名用双引号包起来：两种方言都支持双引号标识符，而 count / since
			// 这类名字在别的上下文里有特殊含义，裸写虽然通常也能解析，但不值得赌。
			"count": gorm.Expr(
				`CASE WHEN "since" <= ? THEN 1 ELSE "count" + 1 END`, cutoff),
			"since": gorm.Expr(
				`CASE WHEN "since" <= ? THEN ? ELSE "since" END`, cutoff, now.Unix()),
			"updated_at": now,
		}),
	}).Create(&row).Error
}

// count 返回窗口内的失败次数，以及这个数字是否完整可信。
//
// # 为什么读失败时不能返回「本实例补记数 + ok=true」
//
// 这是本函数原先的写法，也是缺陷 6：读库失败时返回 c.missed.count(...)，
// 那个值在没有写库失败的情况下**就是 0**。而 count 的唯一用途是
// CaptchaRequired 的阈值判定，于是：
//
//	数据库短暂读故障 → 读到 0 → 未达阈值 → 不要求验证码
//
// 多实例下这是个可利用的绕过：攻击者只要等到（或制造）一次数据库抖动，
// 就能让账号级验证码阈值失效；而账号级验证码恰恰是分布式爆破的唯一克星
// （硬锁按「账号+IP」计，分布式来源每个 IP 各有额度）。
//
// 所以这里改成两件事：
//   - 第二个返回值 ok=false 表示「这个数是不完整的」，由调用方按更严格的
//     方向处理（见 CaptchaRequired）；
//   - 同时置降级标志并计入降级计数，供健康检查/管理页展示，
//     用 logThrottled 告警（限流，避免抖动期间刷屏）。
//
// 返回值仍然给出补记数（而不是 0）：调用方若需要「至少有这么多」时
// 可以直接用，但**不能**把它当成完整计数。
//
// # 恢复
//
// 降级标志只在读成功后清除：一次成功的读说明数据库又看得见了，
// 此时库里的计数（加上补记）是完整的。
func (c *dbLoginFailureCounter) count(account string, now time.Time) (int, bool) {
	account = normalizeAccount(account)
	if account == "" {
		return 0, true
	}
	// 读库为唯一事实源。
	//
	// 曾经在 Redis 里再存一份并优先读它：写 Redis 失败时会回落到数据库，
	// 而读又优先信任 Redis，两条路径一旦分叉，读到的是偏低的值——攻击者
	// 只要卡住一次 Redis 写入，就能让账号级验证码阈值在这个窗口里失效，
	// 且没有任何报错。数据库的 upsert 本来就是原子的、多实例共享的，
	// 这里不再引入第二种权威。
	//
	// 补记表是进程内的，它的 count 永远可信（第二个返回值恒为 true），
	// 这里显式丢弃：本函数自己的可信度只取决于**读库**是否成功。
	missed, _ := c.missed.count(account, now)
	n, err := c.read(account, now)
	if err != nil {
		// 读不到：这个数不完整，方向必须是 fail-closed。
		//
		// 不缓存历史值到进程内（见文件头）：那会让别的实例上的
		// 「登录成功清零」失效，本实例拿着旧值继续要求验证码。
		c.markDegraded()
		c.logDegradedThrottled(err)
		return missed, false
	}
	c.markRecovered()
	return n + missed, true
}

// markDegraded 记录「本次读库失败，计数已降级」。
//
// 两个动作分开看：
//   - degraded 置位：给 CaptchaRequired / 健康检查一个可查询的信号，
//     不再依赖「有人恰好看到了那行日志」；
//   - degradedTotal 累加：抖动可能反复发生，累计次数能说明「这是常态还是
//     一次性故障」，而布尔标志只能说明「刚刚发生过」。
//
// 用 atomic 而不是加锁：这条路径在登录热路径上，且只是两个独立的计数器，
// 不需要原子性地一起更新（读到「标志已置位、计数还没加」不会导致误判，
// 两个方向都是 fail-closed）。
func (c *dbLoginFailureCounter) markDegraded() {
	c.degraded.Store(true)
	c.degradedTotal.Add(1)
}

// markRecovered 在读成功后清除降级标志。降级累计次数不清：它是历史事实。
func (c *dbLoginFailureCounter) markRecovered() {
	c.degraded.Store(false)
}

// read 做一次主键等值查询。
func (c *dbLoginFailureCounter) read(account string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()

	var row model.LoginFailCounter
	err := c.db.WithContext(ctx).Where("account = ?", account).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	// 过期的行不立刻删：下次 record 会用 upsert 把它覆盖成新窗口，
	// 没必要为一次读多拿一次写锁（与内存版同一个取舍）。
	if now.Sub(time.Unix(row.Since, 0)) >= loginFailWindow {
		return 0, nil
	}
	return row.Count, nil
}

// reset 在登录成功时清零。
//
// 必须落库：只在内存里清的话，别的实例上那条记录还在，账号会继续被要求
// 验证码——用户明明刚登录成功，换个实例却又要人机验证，这正是「连续失败」
// 语义被破坏的样子。
func (c *dbLoginFailureCounter) reset(account string) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}
	c.missed.reset(account)

	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()
	if err := c.db.WithContext(ctx).Where("account = ?", account).
		Delete(&model.LoginFailCounter{}).Error; err != nil {
		c.logThrottled(&c.lastWriteErrAt, "清除", err)
	}
}

// LoginFailDegraded 报告账号级失败计数当前是否处于降级状态。
//
// 降级意味着「最近一次读库失败，跨实例的失败计数暂时不可信」——
// 此时 CaptchaRequired 会按 fail-closed 处理（见它的注释），
// 账号级验证码阈值在多实例下只在单实例范围内成立。
//
// 供健康检查与管理页展示。为什么需要它能被查询：
//   - 原先降级只留下一行限流日志，日志会被滚动掉，运维无从判断
//     「刚才那波登录异常时防线是不是弱了」；
//   - 多实例部署里这是个**安全状态**而不是性能指标，应该能被告警系统抓取，
//     而不是等出了事再翻日志。
//
// 纯进程内实现永远返回 false：那份计数就在内存里，不存在读不到的情况。
func (s *Services) LoginFailDegraded() bool {
	if s == nil || s.loginFails == nil {
		return false
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return false
	}
	return c.degraded.Load()
}

// LoginFailDegradedTotal 返回累计的计数降级次数（读库失败次数）。
//
// 与 LoginFailDegraded 的区别：那个回答「现在是否降级」，这个回答
// 「一共降级过多少次」。反复抖动与一次性故障在运维判断上完全不同，
// 而布尔值区分不了——攻击者恰好卡在抖动窗口里时，只看到 false/true
// 的翻转是察觉不到规律的。
//
// 不清零：它是历史事实。
func (s *Services) LoginFailDegradedTotal() int64 {
	if s == nil || s.loginFails == nil {
		return 0
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return 0
	}
	return c.degradedTotal.Load()
}

// purgeExpired 分批删除窗口已过期的行，返回删除条数。
//
// 只由后台清理调用（见 maintenance.go 的 RunMaintenance）：计数表按用户名
// 增长，没有清理的话，攻击者用海量随机用户名就能让它无限膨胀——内存版有
// 容量上限，落库版换成「按时间过期」，语义更干净。
//
// 分批删而不是一条语句删干净：这条表的主键是 account、没有自增 id，所以
// 用 pruneTable 那套「先取 id 再按 id 删」用不上，但「大删会长时间占住写锁」
// 的理由完全一样（SQLite 更是整库阻塞）。这里按 account 分批：先取一批
// 过期账号，再按它们删。攻击者用海量随机用户名灌表时，这一步可能就是几十
// 万行——一条 DELETE 会把登录路径上的写全部堵住，而登录路径上正好也在写
// 这张表。
//
// deadline 由调用方传入（维护循环里是整轮共享的那个），不在这里自己算：
// 每张表各算一份预算会让一次维护拖成好几倍时长，而清理是后台任务，慢一点
// 没关系，影响线上请求才是问题。
func (c *dbLoginFailureCounter) purgeExpired(before, deadline time.Time) (int64, error) {
	var total int64
	for {
		ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
		var accounts []string
		err := c.db.WithContext(ctx).Model(&model.LoginFailCounter{}).
			Where("since <= ?", before.Unix()).
			Limit(maintenanceBatchSize).
			Pluck("account", &accounts).Error
		cancel()
		if err != nil {
			return total, err
		}
		if len(accounts) == 0 {
			return total, nil
		}

		n, err := c.deleteAccounts(accounts, before)
		total += n
		if err != nil {
			return total, err
		}
		// 这一批没装满，说明已经清空。
		if len(accounts) < maintenanceBatchSize {
			return total, nil
		}
		if n == 0 {
			// 整批都没删掉（同一批账号在「取」与「删」之间刚好刷新了窗口）：
			// 它们已经不再过期，下一轮查询也不会再返回，但这里必须退出，
			// 否则会拿着同一批账号空转。
			return total, nil
		}
		if time.Now().After(deadline) {
			// 到预算就停：剩下的下一轮接着清。没清完不算失败——过期行多留
			// 一轮不影响正确性（读的时候按 since 判过期，照样视为 0）。
			return total, nil
		}
	}
}

// deleteAccounts 删掉指定账号里**仍然过期**的计数行，返回删除条数。
//
// 条件里再带一次 since：从「取到账号」到「按账号删」之间，同一个账号可能
// 刚好又失败了一次，upsert 把 since 推成了新窗口。只按 account 删会把这份
// 新计数一起抹掉——那是真的丢一次失败判定。带上 since 条件后，这种行会
// 被跳过，留给下一轮。
func (c *dbLoginFailureCounter) deleteAccounts(accounts []string, before time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loginFailDBTimeout)
	defer cancel()
	res := c.db.WithContext(ctx).
		Where("account IN ? AND since <= ?", accounts, before.Unix()).
		Delete(&model.LoginFailCounter{})
	return res.RowsAffected, res.Error
}

// logThrottled 按类型限流地记录一次计数库访问失败。
//
// 限流是必须的：攻击进行中恰好数据库抖动时，每次失败都打一行日志会把
// 磁盘打满，也会把真正的问题淹掉。账号名刻意不写进日志——它是敏感输入
// （可能就是用户在别处用的密码），而这里要说明的只是「计数库现在有问题」。
//
// 日志里点明「已退化」而不是只报错：管理员看到它才知道这段时间的账号级
// 阈值只在单实例内成立，不必去翻代码确认影响面。
func (c *dbLoginFailureCounter) logThrottled(last *atomic.Int64, action string, err error) {
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(loginFailLogInterval) {
		return
	}
	if !last.CompareAndSwap(prev, now) {
		return
	}
	log.Printf("[loginfail] 账号级失败计数%s失败（跨实例累加已退化，本实例仍按补记/库内值判定；"+
		"窗口 %s）: %v", action, loginFailWindow, err)
}

// logDegradedThrottled 是专供「读失败导致降级」的限流日志。
//
// 与 logThrottled 分开一条日志，因为这两件事对运维的含义不同：
//   - 写失败：这一次累加没进库，但**已经记进补记**，判定仍然成立；
//   - 读失败：整个计数不可信，CaptchaRequired 会按 fail-closed 强制要求
//     验证码。用户侧会看到「本来不用验证码，现在要了」——这是有意的，
//     但它说明防线正在靠「多要一次验证码」兜底，需要尽快修数据库。
//
// 两件事共用同一个 lastReadErrAt 会互相压制（读失败限流一次之后，
// 写失败的日志就被吞掉），所以这里用 errLoginFailCounterDegraded 作为
// 日志内容的锚点，而不是再抢一个独立的限流窗口——降级本身已经由
// degraded / degradedTotal 两个字段暴露给外部，日志只是补充。
func (c *dbLoginFailureCounter) logDegradedThrottled(cause error) {
	c.logThrottled(&c.lastReadErrAt, "读取",
		fmt.Errorf("%w: %v", errLoginFailCounterDegraded, cause))
}

// PurgeExpiredLoginFails 清理窗口已过期的计数行，返回删除条数。
//
// 由后台维护任务周期性调用（见 maintenance.go），deadline 是整轮维护共享的
// 时间预算。纯进程内实现没有落库行，直接返回 0。
func (s *Services) PurgeExpiredLoginFails(before, deadline time.Time) int64 {
	if s == nil || s.loginFails == nil {
		return 0
	}
	c, ok := s.loginFails.(*dbLoginFailureCounter)
	if !ok {
		return 0
	}
	n, err := c.purgeExpired(before, deadline)
	if err != nil {
		// 已经删掉的那部分照样返回：清理是尽力而为，报错只说明这一轮没走完，
		// 下一轮会接着清。
		log.Printf("[loginfail] 清理过期失败计数出错（本轮已清理 %d 条，下一轮维护会重试）: %v", n, err)
		return n
	}
	if n > 0 {
		log.Printf("[loginfail] 已清理 %d 条过期的账号级失败计数", n)
	}
	return n
}
