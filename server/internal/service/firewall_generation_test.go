package service

import (
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestFirewallPendingGenerationGuardsWrites(t *testing.T) {
	svc := newTestServices(t, nil)

	if err := svc.markFirewallPending(20001, "tcp", true); err != nil {
		t.Fatalf("登记放行待办失败: %v", err)
	}
	if err := svc.markFirewallPending(20001, "tcp", false); err != nil {
		t.Fatalf("登记收回待办失败: %v", err)
	}

	svc.persistPending(20001, pendingFW{open: true, proto: "tcp", gen: 1})

	var rec model.FirewallPending
	if err := svc.DB.First(&rec, 20001).Error; err != nil {
		t.Fatalf("应有一条待办记录: %v", err)
	}
	if rec.Open || rec.Generation != 2 {
		t.Fatalf("旧代写回不应覆盖新代，得到 open=%v gen=%d", rec.Open, rec.Generation)
	}

	svc.dropPending(20001, 1)
	if err := svc.DB.First(&rec, 20001).Error; err != nil {
		t.Fatalf("旧代删除不应影响新代记录: %v", err)
	}

	svc.dropPending(20001, 2)
	if err := svc.DB.First(&rec, 20001).Error; err == nil {
		t.Fatal("同代删除应清除记录")
	}
}

func TestFirewallPendingLoadSeedsGeneration(t *testing.T) {
	svc := newTestServices(t, nil)
	if err := svc.markFirewallPending(20002, "tcp", true); err != nil {
		t.Fatalf("登记待办失败: %v", err)
	}
	svc.persistPending(20002, pendingFW{open: true, proto: "tcp", gen: 1})

	svc.fwPending = nil
	svc.loadPendingFirewall()

	if err := svc.markFirewallPending(20002, "tcp", false); err != nil {
		t.Fatalf("登记待办失败: %v", err)
	}
	svc.persistPending(20002, pendingFW{open: false, proto: "tcp", gen: 1})

	var rec model.FirewallPending
	if err := svc.DB.First(&rec, 20002).Error; err != nil {
		t.Fatalf("应有一条待办记录: %v", err)
	}
	if rec.Open {
		t.Fatal("重启后旧代写回不应覆盖新代")
	}
}
