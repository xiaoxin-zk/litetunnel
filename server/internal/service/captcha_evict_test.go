package service

import (
	"fmt"
	"testing"
	"time"
)

// TestCaptchaEvictKeepsNewest 覆盖「达到上限就整表清空」。
//
// 验证码是一次性的：清表等于让**所有**正在填验证码的用户当场失效。
// 攻击者用随机来源刷满票据表，就能把正常登录一起打掉，而且现象是
// 「验证码总是错」，看不出根因是容量。
func TestCaptchaEvictKeepsNewest(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	s.mu.Lock()
	for i := 0; i < captchaMaxEntries; i++ {
		s.entries[fmt.Sprintf("t-%d", i)] = captchaEntry{
			answer: 1,
			ip:     "127.0.0.1",
			// 到期时间递增：i 越大越晚失效，也就是越该保留。
			expireAt: now.Add(time.Duration(i) * time.Millisecond),
		}
	}
	s.evictLocked(now)
	left := len(s.entries)
	_, newest := s.entries[fmt.Sprintf("t-%d", captchaMaxEntries-1)]
	_, oldest := s.entries["t-0"]
	s.mu.Unlock()

	if left >= captchaMaxEntries {
		t.Fatalf("淘汰后仍有 %d 条，应低于上限 %d", left, captchaMaxEntries)
	}
	if !newest {
		t.Fatal("最晚失效的票据被淘汰了：淘汰应按到期时间从早到晚")
	}
	if oldest {
		t.Fatal("最早失效的票据应被优先淘汰")
	}
}

// TestCaptchaEvictDropsExpiredOnly 确认「只需删过期」时不会误删有效票据。
func TestCaptchaEvictDropsExpiredOnly(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	s.mu.Lock()
	for i := 0; i < captchaMaxEntries; i++ {
		// 一半已过期、一半仍有效。
		expire := now.Add(-time.Minute)
		if i%2 == 0 {
			expire = now.Add(time.Minute)
		}
		s.entries[fmt.Sprintf("t-%d", i)] = captchaEntry{answer: 1, expireAt: expire}
	}
	s.evictLocked(now)
	left := len(s.entries)
	s.mu.Unlock()

	if left != captchaMaxEntries/2 {
		t.Fatalf("只应删掉过期的一半，实际剩 %d 条", left)
	}
}
