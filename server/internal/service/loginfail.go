package service

import (
	"strings"
	"sync"
	"time"
)

const (
	// loginFailWindow 是账号级失败计数的统计窗口。
	//
	// 与原先「查登录日志」的 30 分钟保持一致：正常用户在窗口内不会连续输错
	// 这么多次，而脚本爆破必然触发。
	loginFailWindow = 30 * time.Minute

	// loginFailMaxAccounts 是**进程内**计数表的容量上限，防止被海量随机用户名
	// 撑爆内存。
	//
	// 触顶时不会整体清空（那等于给攻击者一个重置所有计数的开关），
	// 而是优先淘汰「只失败过一次」的条目，见 evictLocked。
	//
	// 数据库版没有这个上限，改用「按窗口过期清理」（见 loginfail_db.go）：
	// 落库之后内存不再随用户名数量增长，磁盘上的行也有确定的生命周期。
	loginFailMaxAccounts = 50000

	// loginFailMaxKeyRunes 是计数键的最大长度（按字符数），与
	// model.LoginFailCounter.Account 的 size:191 保持一致。
	//
	// 为什么要截断而不是丢弃：丢弃等于把这一次失败放过去（fail-open），而截断
	// 只会让超长账号共用同一个计数器——方向是「更早要求验证码」，属于可接受的
	// 失败安全侧。正常账号根本到不了这个长度（用户名限制 32 字符），它只对
	// 「攻击者提交超长字符串」有意义：SQLite 的 TEXT 不校验长度，不截断就能用
	// 几 KB 的用户名把计数表撑大；Postgres 那边则会直接写失败，让每一次超长
	// 用户名登录都走一遍补记与告警日志。
	loginFailMaxKeyRunes = 191
)

// loginFailCounter 是账号级登录失败计数的抽象。
//
// # 为什么要有这一层
//
// 这个计数的**唯一**用途是「该账号连续失败若干次后要求验证码」
// （见 CaptchaRequired）。它的强度必须与部署形态无关：单实例跑在内存里没问题，
// 但一旦前面挂了负载均衡、同一账号的请求被分到不同实例，纯进程内计数就会
// 按实例数衰减——N 个实例意味着攻击者拿到 N 倍额度，阈值形同虚设，而且
// 这种退化没有任何报错、没有任何指标。
//
// 因此默认实现是**数据库版**（dbLoginFailureCounter，见 loginfail_db.go）：
// 主键唯一 + 单条原子 upsert 累加 + 窗口过期重置，SQLite 与 Postgres 都能跑，
// 多实例共用一个库时天然共享同一份计数。
//
// 进程内版本（memoryLoginFailureCounter）保留两个用途：
//   - 数据库版写库失败时的补记表：本次失败仍要算数，否则「数据库写不进去」
//     就等于把账号级防线关掉；
//   - 没有数据库句柄的构造路径（例如后台协程里那个只带部分字段的 Services）。
//
// # 部署形态的限制（必须让运维知道）
//
// 数据库版解决的是**账号级验证码阈值**的跨实例一致性。同一层的
// middleware.LoginGuard（账号 + IP 的硬锁）仍然是进程内的：它的键里带来源
// IP，多实例下锁定状态不共享。多实例部署要么在网关层做会话粘滞，要么接受
// 「硬锁按实例计、账号级验证码兜底」这一组合。README 的「多实例部署」一节
// 与 .env.example 都有同样的说明。
type loginFailCounter interface {
	// record 记一次失败。
	record(account string, now time.Time)
	// count 返回窗口内的失败次数，以及这个数字是否**完整可信**。
	//
	// 第二个返回值是为 fail-closed 准备的，不是装饰。落库版在读库失败时
	// 只能返回本实例的补记数——它可能是 0，也可能只是真实计数的一小部分。
	// 如果签名只给 int，调用方（CaptchaRequired）就只能把「读不到」当成
	// 「没有失败」，多实例下攻击者可以用一次数据库抖动绕开账号级验证码。
	//
	// 所以这里显式区分「数是几」与「数是否可信」，让调用方必须处理后者：
	// ok=false 时调用方按「更严格」的方向走，而不是按数字大小走。
	//
	// 不用 -1 之类的哨兵值：那要求每个调用点都记得判哨兵，漏一处就静默
	// 失效；而两个返回值不判就用不掉（至少会多一个变量），编译器会盯着。
	count(account string, now time.Time) (n int, ok bool)
	// reset 在登录成功时清零。
	reset(account string)
}

// loginFailEntry 是单个账号在窗口内的失败次数。
type loginFailEntry struct {
	count int
	since time.Time // 窗口起点：超过 loginFailWindow 即作废
}

// memoryLoginFailureCounter 按账号累计「连续」登录失败次数，专供账号级验证码判定。
//
// 为什么不查登录日志：那是一条容量有限的异步队列，满了就直接丢弃——这是有意
// 的，写日志绝不能拖住登录判定。但「要不要出验证码」是**认证门槛**，它的数据
// 源不能是可丢弃的：日志一旦积压（数据库慢、写入卡住），分布式来源的账号级
// 防护就会静默退化，而且退化时没有任何报错、没有任何指标。
//
// 所以单独维护一份可靠计数。它只服务于这个判定，不承担审计职责——审计仍然
// 由登录日志负责，两者互不依赖：计数丢了只是让验证码来得晚一点，日志丢了
// 只是少一条证据。反过来把日志当门槛的数据源，就等于让前者的容量决定后者的
// 强度。
type memoryLoginFailureCounter struct {
	mu      sync.Mutex
	entries map[string]loginFailEntry
}

func newMemoryLoginFailureCounter() *memoryLoginFailureCounter {
	return &memoryLoginFailureCounter{entries: make(map[string]loginFailEntry, 64)}
}

// normalizeAccount 是计数键的规范化：写入与查询必须用同一套写法。
//
// 不规范化的话，换个大小写在这里就成了另一个账号：攻击者交替提交 "Admin"
// 与 "admin"，失败次数被摊薄到永远到不了阈值。这个坑与登录锁、
// CheckLoginCaptcha 的调用方是同一个，三处必须用同一套键。
//
// 顺带按字符数截断到 loginFailMaxKeyRunes：落库版的主键列是 varchar(191)，
// 超长用户名不截断的话，Postgres 会直接写失败——每一次超长用户名登录都走一遍
// 补记与限流告警；SQLite 的 TEXT 不校验长度，攻击者能用几 KB 的用户名把表撑大。
// 截断而不是丢弃：丢弃等于把这一次失败放过去（fail-open）。
//
// 截断必须在**规范化之后**做，且两侧（record / count / reset）都走这个函数，
// 否则写入用截断键、查询用完整键，计数就永远读不回来。
func normalizeAccount(account string) string {
	account = strings.ToLower(strings.TrimSpace(account))
	if r := []rune(account); len(r) > loginFailMaxKeyRunes {
		account = string(r[:loginFailMaxKeyRunes])
	}
	return account
}

// record 记一次失败。
func (c *memoryLoginFailureCounter) record(account string, now time.Time) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[account]
	if !ok || now.Sub(e.since) >= loginFailWindow {
		if len(c.entries) >= loginFailMaxAccounts {
			c.evictLocked(now)
		}
		c.entries[account] = loginFailEntry{count: 1, since: now}
		return
	}
	e.count++
	c.entries[account] = e
}

// count 返回窗口内的失败次数。
//
// 纯进程内的实现**永远**返回 ok=true：这份数据就在本进程内存里，
// 不存在「读不到」这个状态，要么读到值、要么根本没有这条记录。
// ok=false 只对落库版有意义（见 dbLoginFailureCounter.count）。
func (c *memoryLoginFailureCounter) count(account string, now time.Time) (int, bool) {
	account = normalizeAccount(account)
	if account == "" {
		return 0, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[account]
	if !ok || now.Sub(e.since) >= loginFailWindow {
		return 0, true
	}
	return e.count, true
}

// reset 在登录成功时清零。
//
// 判定的是「连续」失败：成功一次就说明凭据是对的，继续要求验证码只会
// 惩罚正常用户（例如忘记密码试了几次、后来想起来了）。
func (c *memoryLoginFailureCounter) reset(account string) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, account)
}

// evictLocked 在容量触顶时腾出空间。调用方必须持有 c.mu。
//
// 淘汰顺序是有讲究的：先清过期的（它们本来就该消失），再清「只失败过一次」
// 的——丢掉这种条目最多让某个账号少记一次失败，对判定几乎没有影响。
// 反过来，如果按「最旧优先」淘汰，攻击者只要用海量随机用户名灌满计数表，
// 就能把针对某个真实账号已经攒到阈值的计数一起冲掉，账号级防线随之失效。
func (c *memoryLoginFailureCounter) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.since) >= loginFailWindow {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < loginFailMaxAccounts {
		return
	}

	// 仍然满：一次腾出 1/8，避免每来一个新账号就全表扫一遍。
	target := loginFailMaxAccounts - loginFailMaxAccounts/8
	for k, e := range c.entries {
		if len(c.entries) <= target {
			break
		}
		if e.count <= 1 {
			delete(c.entries, k)
		}
	}
	// 极端情况（表里全是多次失败的账号）：只能按遍历顺序淘汰。
	for k := range c.entries {
		if len(c.entries) <= target {
			break
		}
		delete(c.entries, k)
	}
}
