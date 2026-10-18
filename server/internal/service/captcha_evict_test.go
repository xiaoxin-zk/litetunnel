package service

import (
	"fmt"
	"testing"
	"time"
)

// fillCaptcha 按插入顺序铺满票据表。插入顺序即到期顺序（TTL 固定）。
func fillCaptcha(s *CaptchaStore, expires func(i int) time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < captchaMaxEntries; i++ {
		key := fmt.Sprintf("t-%d", i)
		s.entries[key] = captchaEntry{answer: 1, ip: "127.0.0.1", expireAt: expires(i)}
		s.order = append(s.order, key)
	}
}

// TestCaptchaEvictKeepsNewest 覆盖「达到上限就整表清空」。
//
// 验证码是一次性的：清表等于让**所有**正在填验证码的用户当场失效。
// 攻击者用随机来源刷满票据表，就能把正常登录一起打掉，而且现象是
// 「验证码总是错」，看不出根因是容量。
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

// TestCaptchaEvictStopsAtBatchLimit 确认单次淘汰有上限。
//
// 淘汰跑在写入票据的持锁路径上。没有上限的话，表满时每个新票据都要在锁内
// 处理一大批记录，集中领码就会把正常请求堵在后面。
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

// TestCaptchaDropExpiredOnly 确认只清过期、不误删有效票据。
func TestCaptchaDropExpiredOnly(t *testing.T) {
	s := NewCaptchaStore()
	t.Cleanup(s.Close)

	now := time.Now()
	// 前一半过期、后一半有效。插入顺序与到期顺序一致，队头正好是过期的那批。
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
