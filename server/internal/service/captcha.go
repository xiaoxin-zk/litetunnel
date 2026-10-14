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

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	// captchaTTL 是验证码有效期。过长会放大被批量领取后慢慢试的风险。
	captchaTTL = 5 * time.Minute
	// captchaMaxEntries 是同时在线的验证码上限，防止被刷爆内存。
	captchaMaxEntries = 20000
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
}

// NewCaptchaStore 构造验证码存储。
func NewCaptchaStore() *CaptchaStore {
	s := &CaptchaStore{entries: make(map[string]captchaEntry)}
	go s.gc()
	return s
}

func (s *CaptchaStore) gc() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.entries {
			if now.After(e.expireAt) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
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
	// 容量保护：达到上限时直接清空，宁可让少数人重取也不让内存无限增长。
	if len(s.Captchas.entries) >= captchaMaxEntries {
		s.Captchas.entries = make(map[string]captchaEntry)
	}
	s.Captchas.entries[ticket] = captchaEntry{
		answer:   answer,
		ip:       ip,
		expireAt: time.Now().Add(captchaTTL),
	}
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
func (s *Services) CaptchaRequired(kind, account string) bool {
	switch kind {
	case "register":
		return s.Settings.Bool(KeyRegisterCaptcha)
	case "login":
		threshold := s.Settings.Int(KeyLoginCaptchaAfter)
		if threshold <= 0 {
			return false
		}
		n := s.CountRecentFailedLogins(model.LoginKindUser, account, 30*time.Minute)
		n += s.CountRecentFailedLogins(model.LoginKindAdmin, account, 30*time.Minute)
		return int(n) >= threshold
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
