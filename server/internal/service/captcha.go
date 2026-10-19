package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// captchaTTL 是验证码有效期。过长会放大被批量领取后慢慢试的风险。
	captchaTTL = 5 * time.Minute
	// captchaMaxEntries 是同时在线的验证码上限，防止被刷爆内存。
	captchaMaxEntries = 20000
	// captchaEvictBatch 是单次淘汰最多处理的条数。
	//
	// 淘汰发生在写入验证码的持锁路径上：把「一次处理多少条」钉死，才能保证
	// 无论表多大，单次请求在锁内的开销都是有界的。
	captchaEvictBatch = 512
)

// Captcha 是一次性算术验证码。
//
// 为什么不用图形验证码：图形码要么依赖第三方服务，要么需要 cgo 图像库，
// 对一个轻量平台不划算。算术题配合「连续失败若干次后才要求」的策略，
// 已经足以挡住绝大多数脚本化爆破，且没有任何外部依赖。
type Captcha struct {
	Ticket   string `json:"ticket"`
	Question string `json:"question"`
	ExpireIn int    `json:"expire_in"`
}

type captchaEntry struct {
	answer   int
	ip       string
	expireAt time.Time
}

// CaptchaStore 是验证码的内存存储。
//
// 只存内存：验证码本就是短生命周期的临时数据，重启后失效符合预期，
// 也不需要为它引入 Redis。
type CaptchaStore struct {
	mu      sync.Mutex
	entries map[string]captchaEntry

	// order 是票据的插入顺序（FIFO），head 是尚未消费的位置。
	//
	// 有了它，清理与淘汰都不必遍历整张表：TTL 固定，插入顺序就是到期顺序，
	// 队头就是最早到期的那一批。旧实现每次触顶都要在全局锁内扫 2 万条，
	// 集中领码时正常请求会跟着排队。
	order []string
	head  int

	// stop 用于结束 gc 协程（见 Close）。
	stop      chan struct{}
	closeOnce sync.Once
}

// NewCaptchaStore 构造验证码存储。
func NewCaptchaStore() *CaptchaStore {
	s := &CaptchaStore{
		entries: make(map[string]captchaEntry),
		stop:    make(chan struct{}),
	}
	go s.gc()
	return s
}

// Close 停止后台清理协程。
//
// 验证码本身就是短命数据，关闭不必清表：进程退出后它们随内存一起消失，
// 重启后票据本就应该失效。Close 只负责不让那个 ticker 协程活过使用者。
// 可重复调用。
func (s *CaptchaStore) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.stop) })
}

// evictLocked 在容量触顶时腾出空间。调用方必须持有 s.mu。
//
// 不整表清空。旧实现是「满了就换一张新表」，代价不只是内存：验证码是
// 一次性的，清表等于让**所有**正在填验证码的用户当场失效——攻击者用
// 随机来源刷满票据表，就能把正常登录一起打掉，而且看起来像「验证码
// 总是错」，没有任何线索指向容量。
//
// 先清过期（只需看队头），仍然满再从队头硬删——单次最多 captchaEvictBatch 条。
// 全程不遍历整表，单次持锁开销与表大小无关。
func (s *CaptchaStore) evictLocked(now time.Time) {
	s.dropExpiredLocked(now)
	if len(s.entries) < captchaMaxEntries {
		return
	}

	// 一次腾出一批空间（降到 floor 以下或删满 batch），而不是「删一条
	// 就低于上限」——后者会让下一次写入立刻又触顶，淘汰变成每个请求都做。
	floor := captchaMaxEntries - captchaEvictBatch
	removed := 0
	for s.head < len(s.order) && removed < captchaEvictBatch && len(s.entries) > floor {
		key := s.order[s.head]
		s.head++
		if _, ok := s.entries[key]; !ok {
			continue // 已经被验证消费掉
		}
		delete(s.entries, key)
		removed++
	}
	s.compactOrderLocked()
}

// dropExpiredLocked 从队头清理过期票据。调用方必须持有 s.mu。
//
// 插入顺序即到期顺序（TTL 固定），所以扫到第一个未过期的就可以停：
// 它后面的都还没到期。O(过期条数)，而不是 O(表大小)。
func (s *CaptchaStore) dropExpiredLocked(now time.Time) {
	for s.head < len(s.order) {
		key := s.order[s.head]
		e, ok := s.entries[key]
		if !ok {
			s.head++
			continue
		}
		if now.Before(e.expireAt) {
			break
		}
		delete(s.entries, key)
		s.head++
	}
	s.compactOrderLocked()
}

// compactOrderLocked 回收队头已经消费掉的空间。
//
// 不回收的话 order 会随「累计发出过的票据数」一直增长——虽然每项只是一个
// 指针，但那是整段进程生命周期里只增不减的量。
func (s *CaptchaStore) compactOrderLocked() {
	if s.head < 1024 || s.head*2 < len(s.order) {
		return
	}
	s.order = append([]string(nil), s.order[s.head:]...)
	s.head = 0
}

func (s *CaptchaStore) gc() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.dropExpiredLocked(time.Now())
			s.mu.Unlock()
		}
	}
}

// NewCaptcha 生成一道算术题并返回票据。
func (s *Services) NewCaptcha(ip string) (*Captcha, error) {
	if s.Captchas == nil {
		return nil, errors.New("验证码服务未初始化")
	}
	a, err := randInt(2, 9)
	if err != nil {
		return nil, err
	}
	b, err := randInt(2, 9)
	if err != nil {
		return nil, err
	}
	// 随机决定是否用加法/减法，避免答案永远是「两个数相加」被脚本直接算出来。
	question := fmt.Sprintf("%d + %d = ?", a, b)
	answer := a + b
	if a > b {
		if op, err := randInt(0, 1); err == nil && op == 1 {
			question = fmt.Sprintf("%d - %d = ?", a, b)
			answer = a - b
		}
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	ticket := hex.EncodeToString(buf)

	s.Captchas.mu.Lock()
	// 容量保护：按到期时间淘汰，**不**整表清空（见 evictLocked）。
	if len(s.Captchas.entries) >= captchaMaxEntries {
		s.Captchas.evictLocked(time.Now())
	}
	s.Captchas.entries[ticket] = captchaEntry{
		answer:   answer,
		ip:       ip,
		expireAt: time.Now().Add(captchaTTL),
	}
	// 插入顺序就是到期顺序（TTL 固定），清理与淘汰都靠这条队列定位队头。
	// 票据被消费时不从队列里删（那需要额外查找），推进队头时跳过即可。
	s.Captchas.order = append(s.Captchas.order, ticket)
	s.Captchas.mu.Unlock()

	return &Captcha{
		Ticket:   ticket,
		Question: question,
		ExpireIn: int(captchaTTL.Seconds()),
	}, nil
}

// CheckCaptcha 校验并消费验证码。验证码是一次性的，无论对错都会被删除。
//
// 一次性是刻意的：否则攻击者可以拿一张票反复试答案。
func (s *Services) CheckCaptcha(ticket, answer string) bool {
	if s.Captchas == nil || ticket == "" {
		return false
	}
	s.Captchas.mu.Lock()
	entry, ok := s.Captchas.entries[ticket]
	delete(s.Captchas.entries, ticket)
	s.Captchas.mu.Unlock()

	if !ok || time.Now().After(entry.expireAt) {
		return false
	}
	got, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(
		[]byte(strconv.Itoa(entry.answer)), []byte(strconv.Itoa(got))) == 1
}

// CaptchaRequired 判断当前是否必须提供验证码。
//
// 策略：注册场景由开关控制；登录场景只在「该账号已连续失败若干次」后才要求，
// 这样正常用户无感，而脚本爆破必然触发。
//
// 计数取自 loginFailCounter（默认落库，见 loginfail_db.go），而不是登录日志：
// 后者是容量有限的异步队列，满了会丢弃（写日志不能拖住登录判定）。把认证
// 门槛建在可丢弃的数据上，等于让日志的吞吐决定防线强度——积压时不报错、
// 不告警，只是静默失效，而这恰好发生在数据库慢、攻击最容易得手的时候。
//
// 用共享存储而不是进程内计数，是为了让阈值在多实例部署下仍然成立：进程内
// 计数会被负载均衡按实例数摊薄，N 个实例等于 N 倍额度。
//
// # 计数读不出来时要求验证码（fail-closed）
//
// count 的第二个返回值是「这个数字是否完整可信」。读库失败时它返回
// ok=false：只能拿到本实例的补记数，而那通常就是 0。如果这里照旧拿 0 去
// 比阈值，多实例下攻击者只需等到一次数据库抖动就能让账号级验证码失效——
// 而账号级验证码是分布式爆破的唯一克星（硬锁按「账号+IP」计，分布式来源
// 每个 IP 各有额度）。
//
// 所以 ok=false 时直接要求验证码：多要一次人机验证，代价是一次点击；
// 放过去的代价是整条账号级防线在那段时间里不存在。两个方向不对称，
// 只能选严格的那一边。
//
// 注意这不是「永久降级」：dbLoginFailureCounter 在读成功后立刻清除降级
// 标志（见 markRecovered），下一次判定就恢复正常。降级状态本身可以通过
// Services.LoginFailDegraded 查询，供健康检查/管理页展示。
func (s *Services) CaptchaRequired(kind, account string) bool {
	switch kind {
	case "register":
		return s.Settings.Bool(KeyRegisterCaptcha)
	case "login":
		threshold := s.Settings.Int(KeyLoginCaptchaAfter)
		if threshold <= 0 {
			return false
		}
		if s.loginFails == nil {
			return false
		}
		n, ok := s.loginFails.count(account, time.Now())
		if !ok {
			// 计数不可信：不能拿「可能是 0 的补记数」去比阈值。
			return true
		}
		return n >= threshold
	default:
		return false
	}
}

func randInt(min, max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}
