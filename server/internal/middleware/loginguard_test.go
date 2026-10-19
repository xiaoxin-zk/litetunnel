package middleware

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginGuardEvictKeepsLockedRecords(t *testing.T) {
	g := NewLoginGuard(3, time.Minute, time.Hour)
	t.Cleanup(g.Close)

	for i := 0; i < 3; i++ {
		g.Fail("login", "admin", "1.2.3.4")
	}
	if ok, _ := g.Check("login", "admin", "1.2.3.4"); ok {
		t.Fatal("构造失败：该来源应已被锁定")
	}

	for i := 0; i < maxLoginRecords; i++ {
		g.Fail("login", fmt.Sprintf("rand-user-%d", i),
			fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}

	if ok, left := g.Check("login", "admin", "1.2.3.4"); ok {
		t.Fatalf("锁定记录被容量淘汰冲掉了（剩余锁定 %v）：攻击者灌表即可解封", left)
	}
}

func TestLoginGuardEvictStaysUnderLimit(t *testing.T) {
	g := NewLoginGuard(3, time.Minute, time.Hour)
	t.Cleanup(g.Close)

	for i := 0; i < maxLoginRecords+1000; i++ {
		g.Fail("login", fmt.Sprintf("u%d", i), "127.0.0.1")
	}

	if n := g.size(); n > maxLoginRecords {
		t.Fatalf("记录表大小 %d 超过上限 %d", n, maxLoginRecords)
	}
}
