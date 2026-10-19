package service

import (
	"fmt"
	"testing"
	"time"
)

func fillCaptcha(s *CaptchaStore, expires func(i int) time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < captchaMaxEntries; i++ {
		key := fmt.Sprintf("t-%d", i)
		s.entries[key] = captchaEntry{answer: 1, ip: "127.0.0.1", expireAt: expires(i)}
		s.order = append(s.order, key)
	}
}

func TestCaptchaEvictKeepsNewest(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	fillCaptcha(s, func(int) time.Time { return now.Add(captchaTTL) })

	s.mu.Lock()
	s.evictLocked(now)
	left := len(s.entries)
	_, newest := s.entries[fmt.Sprintf("t-%d", captchaMaxEntries-1)]
	_, oldest := s.entries["t-0"]
	s.mu.Unlock()

	if left >= captchaMaxEntries {
		t.Fatalf("淘汰后仍有 %d 条，应低于上限 %d", left, captchaMaxEntries)
	}
	if !newest {
		t.Fatal("最新发出的票据被淘汰了：淘汰应从队头（最早发出的）开始")
	}
	if oldest {
		t.Fatal("最早的票据应被优先淘汰")
	}
}

func TestCaptchaEvictStopsAtBatchLimit(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	fillCaptcha(s, func(int) time.Time { return now.Add(captchaTTL) })

	s.mu.Lock()
	s.evictLocked(now)
	left := len(s.entries)
	s.mu.Unlock()

	if want := captchaMaxEntries - captchaEvictBatch; left != want {
		t.Fatalf("单次应只淘汰 %d 条，实际剩 %d 条", captchaEvictBatch, left)
	}
}

func TestCaptchaDropExpiredOnly(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	fillCaptcha(s, func(i int) time.Time {
		if i < captchaMaxEntries/2 {
			return now.Add(-time.Minute)
		}
		return now.Add(time.Minute)
	})

	s.mu.Lock()
	s.dropExpiredLocked(now)
	left := len(s.entries)
	s.mu.Unlock()

	if left != captchaMaxEntries/2 {
		t.Fatalf("只应删掉过期的一半，实际剩 %d 条", left)
	}
}
