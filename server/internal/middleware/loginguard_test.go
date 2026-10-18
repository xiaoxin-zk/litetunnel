package middleware

import (
	"fmt"
	"testing"
	"time"
)

// TestLoginGuardEvictKeepsLockedRecords 覆盖「容量触顶时整表清空」。
//
// 旧实现满了就换一张新表：攻击者用海量随机账号/IP 灌满记录表，正在被
// 锁定的真实账号会跟着一起解封——而灌表恰好发生在攻击中途，等于在攻击者
// 最需要的时候把锁定撤掉。淘汰必须按代价从低到高：锁定中的记录最后才动。
func TestLoginGuardEvictKeepsLockedRecords(t *testing.T) {
	g := NewLoginGuard(3, time.Minute, time.Hour)
	t.Cleanup(g.Close)

	for i := 0; i < 3; i++ {
		g.Fail("login", "admin", "1.2.3.4")
	}
	if ok, _ := g.Check("login", "admin", "1.2.3.4"); ok {
		t.Fatal("构造失败：该来源应已被锁定")
	}

	// 灌满容量：每个随机来源只失败一次，全部未锁定。
	for i := 0; i < maxLoginRecords; i++ {
		g.Fail("login", fmt.Sprintf("rand-user-%d", i),
			fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}

	if ok, left := g.Check("login", "admin", "1.2.3.4"); ok {
		t.Fatalf("锁定记录被容量淘汰冲掉了（剩余锁定 %v）：攻击者灌表即可解封", left)
	}
}

// TestLoginGuardEvictStaysUnderLimit 确认淘汰确实把表压回上限以内。
func TestLoginGuardEvictStaysUnderLimit(t *testing.T) {
	g := NewLoginGuard(3, time.Minute, time.Hour)
	t.Cleanup(g.Close)

	for i := 0; i < maxLoginRecords+1000; i++ {
		g.Fail("login", fmt.Sprintf("u%d", i), "127.0.0.1")
	}

	g.mu.Lock()
	n := len(g.records)
	g.mu.Unlock()
	if n > maxLoginRecords {
		t.Fatalf("记录表大小 %d 超过上限 %d", n, maxLoginRecords)
	}
}
