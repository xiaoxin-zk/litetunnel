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

	// loginFailMaxAccounts 是计数表的容量上限，防止被海量随机用户名撑爆内存。
	//
	// 触顶时不会整体清空（那等于给攻击者一个重置所有计数的开关），
	// 而是优先淘汰「只失败过一次」的条目，见 evictLocked。
	loginFailMaxAccounts = 50000
)

// loginFailEntry 是单个账号在窗口内的失败次数。
type loginFailEntry struct {
	count int
	since time.Time // 窗口起点：超过 loginFailWindow 即作废
}

// loginFailureCounter 按账号累计「连续」登录失败次数，专供账号级验证码判定。
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
type loginFailureCounter struct {
	mu      sync.Mutex
	entries map[string]loginFailEntry
}

func newLoginFailureCounter() *loginFailureCounter {
	return &loginFailureCounter{entries: make(map[string]loginFailEntry, 64)}
}

// normalizeAccount 是计数键的规范化：写入与查询必须用同一套写法。
//
// 不规范化的话，换个大小写在这里就成了另一个账号：攻击者交替提交 "Admin"
// 与 "admin"，失败次数被摊薄到永远到不了阈值。这个坑与登录锁、
// CheckLoginCaptcha 的调用方是同一个，三处必须用同一套键。
func normalizeAccount(account string) string {
	return strings.ToLower(strings.TrimSpace(account))
}

// record 记一次失败。
func (c *loginFailureCounter) record(account string, now time.Time) {
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

// count 返回窗口内的失败次数。窗口过期即视为 0，且不立刻删除条目——
// 下次 record 会把它覆盖掉，没必要为一次读多拿一次写锁。
func (c *loginFailureCounter) count(account string, now time.Time) int {
	account = normalizeAccount(account)
	if account == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[account]
	if !ok || now.Sub(e.since) >= loginFailWindow {
		return 0
	}
	return e.count
}

// reset 在登录成功时清零。
//
// 判定的是「连续」失败：成功一次就说明凭据是对的，继续要求验证码只会
// 惩罚正常用户（例如忘记密码试了几次、后来想起来了）。
func (c *loginFailureCounter) reset(account string) {
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
func (c *loginFailureCounter) evictLocked(now time.Time) {
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
