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
	captchaTTL        = 5 * time.Minute
	captchaMaxEntries = 20000
	captchaEvictBatch = 512
)

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

type CaptchaStore struct {
	mu      sync.Mutex
	entries map[string]captchaEntry

	order []string
	head  int

	stop      chan struct{}
	closeOnce sync.Once
}

func NewCaptchaStore() *CaptchaStore {
	s := &CaptchaStore{
		entries: make(map[string]captchaEntry),
		stop:    make(chan struct{}),
	}
	go s.gc()
	return s
}

func (s *CaptchaStore) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.stop) })
}

func (s *CaptchaStore) evictLocked(now time.Time) {
	s.dropExpiredLocked(now)
	if len(s.entries) < captchaMaxEntries {
		return
	}

	floor := captchaMaxEntries - captchaEvictBatch
	removed := 0
	for s.head < len(s.order) && removed < captchaEvictBatch && len(s.entries) > floor {
		key := s.order[s.head]
		s.head++
		if _, ok := s.entries[key]; !ok {
			continue
		}
		delete(s.entries, key)
		removed++
	}
	s.compactOrderLocked()
}

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
	if len(s.Captchas.entries) >= captchaMaxEntries {
		s.Captchas.evictLocked(time.Now())
	}
	s.Captchas.entries[ticket] = captchaEntry{
		answer:   answer,
		ip:       ip,
		expireAt: time.Now().Add(captchaTTL),
	}
	s.Captchas.order = append(s.Captchas.order, ticket)
	s.Captchas.mu.Unlock()

	return &Captcha{
		Ticket:   ticket,
		Question: question,
		ExpireIn: int(captchaTTL.Seconds()),
	}, nil
}

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
