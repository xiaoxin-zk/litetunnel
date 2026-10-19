package service

import (
	"strings"
	"sync"
	"time"
)

const (
	loginFailWindow = 30 * time.Minute

	loginFailMaxAccounts = 50000

	loginFailMaxKeyRunes = 191
)

type loginFailCounter interface {
	record(account string, now time.Time)
	count(account string, now time.Time) (n int, ok bool)
	reset(account string)
}

type loginFailEntry struct {
	count int
	since time.Time
}

type memoryLoginFailureCounter struct {
	mu      sync.Mutex
	entries map[string]loginFailEntry
}

func newMemoryLoginFailureCounter() *memoryLoginFailureCounter {
	return &memoryLoginFailureCounter{entries: make(map[string]loginFailEntry, 64)}
}

func normalizeAccount(account string) string {
	account = strings.ToLower(strings.TrimSpace(account))
	if r := []rune(account); len(r) > loginFailMaxKeyRunes {
		account = string(r[:loginFailMaxKeyRunes])
	}
	return account
}

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

func (c *memoryLoginFailureCounter) reset(account string) {
	account = normalizeAccount(account)
	if account == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, account)
}

func (c *memoryLoginFailureCounter) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.since) >= loginFailWindow {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < loginFailMaxAccounts {
		return
	}

	target := loginFailMaxAccounts - loginFailMaxAccounts/8
	for k, e := range c.entries {
		if len(c.entries) <= target {
			break
		}
		if e.count <= 1 {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) <= target {
			break
		}
		delete(c.entries, k)
	}
}
